*[Read in English](CHANGELOG_FULL.md)* · *[TL;DR](../CHANGELOG_FR.md)*

# BOB — Bodyguard Of Bits — Journal des modifications

Toutes les modifications notables du projet sont documentées ici.

---

## [v0.2.3] — 03-05-2026

Huit corrections identifiées lors d'une tournée d'audit multi-VM systématique (Linux Mint desktop, Debian 13, Kali, VM Linux Mint, Ubuntu 26.04). Trois corrections comportementales dans la couche de vérification, deux corrections infrastructure, et trois corrections de précision UX trouvées par comparaison multi-distros. Aucune nouvelle fonctionnalité. 4262/4262 tests (+1).

---

### Fix 1 — NOT_LISTENING toujours INFO (`bob/checks/services.py`, `tests/test_services.py`)

#### Problème

`_check_exposure()` dans `services.py` comportait une branche conditionnelle sur la sévérité pour `Exposure.NOT_LISTENING` :

```python
elif exposure == Exposure.NOT_LISTENING:
    if snap.service.is_high_or_critical:
        result.warn(message=port_msg, nature="improvement")
    else:
        result.info(message=port_msg)
```

Pour les services CRITIQUE/ÉLEVÉ (ex. Mosquitto, Redis, SSH) avec un port enregistré mais non lié activement, cela produisait un finding `⚠ [ATTENTION]` avec `nature="improvement"`. Ce finding apparaissait dans la boîte résumé sous "⚠ Améliorations possibles", alors qu'un port qui n'écoute pas est un état neutre — le service n'expose pas le port, ce qui est favorable.

Trouvé sur : Linux Mint desktop (Telnet NOT_LISTENING dans le résumé malgré l'absence d'installation) et VM Linux Mint (Mosquitto 8883 en WARN alors que seul 1883 était lié).

#### Correction

```python
elif exposure == Exposure.NOT_LISTENING:
    result.info(message=port_msg)
```

La branche conditionnelle sur la sévérité est supprimée. `NOT_LISTENING` est informationnel sur tous les services.

---

### Fix 2 — Dominance locale IoT : déduction supprimée (`bob/checks/logs.py`, `tests/test_logs.py`)

#### Problème

`_check_local_dominance()` détecte quand une seule IP privée domine les logs UFW bloqués — pattern causé par des appareils IoT diffusant en UDP sur le réseau local. Précédemment :

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

Déduire 1 point pour du trafic IoT bénin était incorrect. La fonction identifiait déjà la source comme une adresse privée et la qualifiait de pattern faible sévérité ; pénaliser le score était contradictoire.

Trouvé sur : Linux Mint desktop (score inférieur aux attentes ; diffusion IoT d'une prise connectée réduisant le score de 1 pt).

#### Correction

```python
result.info(
    message=_t("logs.local_dominance", ...),
    key="logs.local_dominance",
)
```

Rétrogradé en `result.info()`, sans déduction. Le message informatif reste visible dans l'audit complet.

---

### Fix 3 — Heredoc non tronqué (`bob/display.py`)

#### Problème

`_add_finding_lines()` passait la chaîne `item.cmd` entière à `_wrap_for_box()` :

```python
for content, val in _wrap_for_box(cmd_prefix, item.cmd, inner):
    lines.append(...)
```

`_wrap_for_box()` appelle `text.split()` en interne, qui découpe sur tous les espaces blancs y compris `\n`. Les commandes multi-lignes (blocs heredoc dans les étapes de remédiation auditd) étaient fusionnées en une seule ligne continue, les rendant illisibles.

Trouvé sur : Linux Mint desktop (bloc heredoc auditd affiché sur une seule ligne dans la boîte résumé).

#### Correction

```python
cont_prefix = " " * len(cmd_prefix)
for i, cmd_line in enumerate(item.cmd.splitlines()):
    pfx = cmd_prefix if i == 0 else cont_prefix
    for content, val in _wrap_for_box(pfx, cmd_line, inner):
        lines.append((f"{_oc.violet_bold}{content}{_oc.reset}", val))
```

Chaque ligne de `item.cmd` est traitée indépendamment par `_wrap_for_box()`. Les lignes de continuation utilisent un préfixe aligné (indenté pour correspondre au marqueur `→ ` ou `ℹ ` de la première ligne).

---

### Fix 4 — Garde contre les symlinks circulaires dans `--install-completion` (`bob/completion.py`)

#### Problème

`_install_completion()` vérifiait :

```python
candidate = home / ".local" / "bin" / "bob"
if candidate.exists():
    bin_src = candidate
```

Quand pipx était installé en root (`/usr/local/bin/bob`) et que `--install-completion` était exécuté en tant qu'utilisateur, `~/.local/bin/bob` était déjà un symlink pointant vers le binaire système. L'utiliser comme `bin_src` amenait l'installeur de completion à créer un nouveau symlink au même chemin pointant vers lui-même, produisant une chaîne circulaire (`~/.local/bin/bob → lui-même`).

Trouvé sur : desktop de l'utilisateur après `--install-completion` ; `pipx upgrade` affichait ensuite un avertissement de symlink circulaire.

#### Correction

```python
if candidate.exists() and candidate.resolve() != dst_bin.resolve():
    bin_src = candidate
```

`resolve()` suit tous les symlinks jusqu'au chemin canonique. Si `candidate` et `dst_bin` se résolvent vers le même chemin, le candidat est ignoré et le binaire système est utilisé directement. `exists()` retourne déjà `False` pour les symlinks cassés ou circulaires, donc la vérification combinée couvre tous les cas d'échec.

---

### Fix 5 — Python 3.9 retiré (`pyproject.toml`, `.github/workflows/tests.yml`, `.github/workflows/publish.yml`)

#### Problème

Python 3.9 a atteint sa fin de vie en octobre 2025. `Path.stat()` n'accepte pas `follow_symlinks` en argument nommé avant Python 3.10, causant une `TypeError` dans `tests/test_manage_logs.py` sur le runner CI 3.9.

#### Correction

- `requires-python = ">=3.10"` dans `pyproject.toml` (était `">=3.9"`).
- Classifier Python 3.9 supprimé de `pyproject.toml`.
- Matrice CI dans `tests.yml` et `publish.yml` passée de `["3.9", "3.10", "3.12"]` à `["3.10", "3.12"]`.

---

### Fix 6 — Compare : delta de déductions variables (`bob/compare.py`, locales)

#### Problème

`AuditBaseline` stockait `score`, `alert_count`, `warn_count` et `finding_keys`, mais pas le total des points de déduction bruts. Quand le score changeait entre deux audits sans changement structurel (mêmes clés de findings, mêmes counts alertes/warns — ex. parce que les déductions basées sur les logs variaient avec l'activité réseau), `display_delta()` affichait uniquement :

```
⚠ Score dégradé de N point(s)
```

sans autre explication, empêchant l'utilisateur de comprendre pourquoi le score avait bougé.

Trouvé sur : VM Debian 13 et VM Kali (delta de score sans explication structurelle).

#### Correction

`AuditBaseline` gagne `deduction_total: int = 0` (la valeur par défaut `0` permet le chargement des anciens baselines sans erreur). `AuditDelta` gagne `deduction_delta: int = 0`. `build_baseline()` calcule `sum(d.points for d in engine.breakdown)`. `load_baseline()` lit `raw.get("deduction_total", 0)`.

`display_delta()` affiche le message de déductions variables quand :
- `deduction_delta != 0`, ET
- aucune explication structurelle n'existe (`alert_delta == 0`, `warn_delta == 0`, `new_finding_keys` vide, `resolved_finding_keys` vide).

Nouvelles clés i18n : `compare.variable_deductions_increased`, `compare.variable_deductions_decreased`.

---

### Fix 7 — Surface d'attaque : label SSH scindé (`bob/exposure.py`, locales, `tests/test_exposure.py`)

#### Problème

`compute_exposure()` utilisait une seule clé i18n pour deux états SSH distincts :

```python
if "ssh.not_installed" in all_keys or "ssh.not_active" in bad_keys:
    detail=t("exposure.ssh_not_running")  # "non installé / non démarré"
```

Quand SSH était installé mais son service arrêté (ex. Kali Linux, où `sshd` est intentionnellement inactif), le tableau de surface d'attaque affichait "non installé / non démarré" — factuellement incorrect, le paquet étant présent.

Trouvé sur : VM Kali (SSH installé mais arrêté ; label indiquait "non installé").

#### Correction

```python
if "ssh.not_installed" in all_keys:
    detail=t("exposure.ssh_not_installed")   # "non installé"
elif "ssh.not_active" in bad_keys:
    detail=t("exposure.ssh_stopped")          # "installé — non démarré"
```

La clé `ssh_not_running` est remplacée par deux clés distinctes : `ssh_not_installed` et `ssh_stopped`. Nouveau test : `test_not_active_shows_stopped_text`.

---

### Fix 8 — Services : message `active_disabled` avec label du service (`bob/checks/services.py`, locales)

#### Problème

Quand un service était actif mais non activé au démarrage (`ServiceState.ACTIVE_DISABLED`), le message de finding était :

```
"Le service est actif en ce moment, mais ne redémarrera pas automatiquement."
```

Dans l'audit complet, ce message était contextuellement clair (il apparaissait sous l'en-tête de section `▶ NomDuService`). Dans la boîte résumé, le nom du service était absent, empêchant l'utilisateur d'identifier quel service était concerné sans parcourir l'audit complet.

Trouvé sur : VM Linux Mint (Redis actif mais non activé ; boîte résumé affichait le message sans "Redis").

#### Correction

Chaîne i18n : `"{label} est actif en ce moment, mais ne redémarrera pas automatiquement."` (FR et EN mis à jour). Site d'appel : `_t("services.state.active_disabled", label=snap.label)`.

---

### Tests

4262/4262 (+1 nouveau, 4 renommés/mis à jour) :

| Fichier | Modification |
|---------|-------------|
| `tests/test_services.py` | `test_not_listening_critical_adds_warn` → `_adds_info` · `test_not_listening_high_adds_warn` → `_adds_info` · assertions changées en `has_level(result, "info")` et `not has_level(result, "warn")` |
| `tests/test_logs.py` | `test_finding_is_warn_level` → `test_finding_is_info_level` (asserte `FindingLevel.INFO`) · `test_score_deduction_one_point` → `test_no_score_deduction` (asserte `len(local_deductions) == 0`) |
| `tests/test_exposure.py` | `test_not_installed_info_is_ok` et `test_not_installed_overrides_password_auth` assertent la clé `exposure.ssh_not_installed` · +1 `test_not_active_shows_stopped_text` asserte la clé `exposure.ssh_stopped` |

---

## [v0.2.2] — 03-05-2026

Cinq corrections ciblées du scoring, un fix de locale, une passe d'uniformisation du logging sur trois modules, une correction du check de règle UFW sans protocole, une correction du plafond de domaine (UFW inactif), des tests d'invariants scoring et une documentation de la pondération égale des domaines. 4261/4261 tests (+23).

---

### Fix 1 — Propagation `ScoreCap.key` (`bob/scoring.py`, `bob/checks/firewall.py`)

#### Problème

`ScoreCap` n'avait pas de champ `key`. Quand un plafond se déclenchait, `finalize()` ajoutait une `Deduction` synthétique dans `engine.breakdown` avec `key=""` :

```python
self.breakdown.append(
    Deduction(reason=self._cap.reason, points=delta, context="structural")
)
```

`compute_domain_scores()` ignore les déductions avec `key=""` (`_key_to_domain()` retourne `None` pour les clés vides). Un plafond pare-feu-inactif qui réduisait le score de plusieurs points contribuait zéro aux déductions du domaine `firewall` — le plafond était invisible au scoring par domaine.

#### Correction

`ScoreCap` gagne `key: str = ""` :

```python
@dataclass
class ScoreCap:
    maximum: int
    reason:  str
    key:     str = ""
```

`CheckResult.set_cap()`, `ScoreEngine.cap()` et `ScoreEngine.apply()` propagent tous la clé. `finalize()` utilise `self._cap.key` dans la déduction synthétique :

```python
self.breakdown.append(
    Deduction(reason=self._cap.reason, points=delta, context="structural", key=self._cap.key)
)
```

`bob/checks/firewall.py` mis à jour :

```python
result.set_cap(maximum=3, reason=_t("firewall.inactive"), key="firewall.inactive")
```

---

### Fix 2 — Les findings INFO n'inflatent plus l'ensemble des domaines actifs (`bob/domain_scores.py`)

#### Problème

`active_domains_from_engine()` itérait sur tous les findings sans distinction de niveau :

```python
for finding in engine.findings:
    domain = _key_to_domain(finding.key)
    if domain:
        active.add(domain)
```

Un domaine INFO-only — service installé sans aucun problème actionnable (ex. ClamAV installé, base fraîche, scan récent) — était inclus dans `active_domains` et donc dans la moyenne globale. Cela pouvait soit diluer les scores des domaines réellement dégradés, soit gonfler la moyenne quand un domaine INFO-only avec un score élevé était inclus.

#### Correction

`FindingLevel` importé directement depuis `bob.scoring`. Les boucles de findings filtrent maintenant à WARN et ALERT uniquement :

```python
_actionable = (FindingLevel.WARN, FindingLevel.ALERT)
for finding in engine.findings:
    if finding.level not in _actionable:
        continue
    domain = _key_to_domain(finding.key)
    if domain:
        active.add(domain)
```

La boucle des déductions reste inchangée — un domaine avec des déductions mais sans finding WARN/ALERT (cas limite) est toujours compté comme actif via le chemin déductions.

---

### Fix 3 — `clamav.db_very_outdated` 2pt → 1pt (`bob/checks/clamav.py`)

#### Problème

`check_clamav()` émettait une déduction de 2 points pour `clamav.db_very_outdated` (base de données ≥ 30 jours). L'entrée `clamav` dans `_TOOL_CAPS` plafonne la contribution de l'outil à 1 point par domaine. Le deuxième point n'affectait que `engine._raw_score` avant la moyenne par domaine, créant une asymétrie silencieuse : le score brut pénalisait ce finding deux fois plus fort que le score par domaine.

#### Correction

```python
# avant
result.add_deduction(
    reason=_t("clamav.db_very_outdated", days=snapshot.db_age_days),
    points=2, context="local", key="clamav.db_very_outdated",
)

# après
result.add_deduction(
    reason=_t("clamav.db_very_outdated", days=snapshot.db_age_days),
    points=1, context="local", key="clamav.db_very_outdated",
)
```

Total de déductions ClamAV en pire cas : `freshclam:1 + db_very_outdated:1 + scan_very_old:1 = 3` (était 4).

---

### Observabilité — logging uniformisé (`bob/history.py`, `bob/ignore.py`, `bob/sysinfo.py`)

Six gestionnaires `except … pass` remplacés par `_log.debug()`. `import logging` et `_log = logging.getLogger(__name__)` ajoutés aux trois modules. Les échecs restent non-fatals ; visibles avec `--debug`.

#### `bob/history.py`

```python
# save_score() — avant
except OSError:
    pass

# save_score() — après
except OSError as exc:
    _log.debug("Failed to save score to history: %s", exc)

# _rotate_if_needed() — avant
except OSError:
    pass

# _rotate_if_needed() — après
except OSError as exc:
    _log.debug("Failed to rotate history file: %s", exc)
```

#### `bob/ignore.py`

```python
# load_ignore_keys() — avant
except OSError:
    pass

# load_ignore_keys() — après
except OSError as exc:
    _log.debug("Cannot read ignore file %s: %s", path, exc)
```

#### `bob/sysinfo.py`

`get_user_home()` : SUDO_USER défini mais absent de la base de données des mots de passe — le repli sur `Path.home()` est maintenant loggé, ce qui explique les chemins de configuration inattendus lors de l'exécution avec des configurations sudo exotiques.

`collect_system_info()` : l'échec de lecture de `/etc/os-release` est maintenant loggé.

`detect_network_type()` : les deux échecs subprocess (`ip route` et `ip addr`) sont maintenant loggés. Auparavant, ces échecs silencieux faisaient tomber la fonction sur `get_public_ip()` sans aucune trace.

```python
# detect_network_type() — avant (deux emplacements)
except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
    pass

# detect_network_type() — après
except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
    _log.debug("ip route failed during network type detection: %s", exc)
    # (et séparément pour ip addr)
    _log.debug("ip addr failed during network type detection: %s", exc)
```

---

### Contrat scoring documenté (`bob/scoring.py`)

Docstring de `ScoreEngine.finalize()` mise à jour :

```
Required call sequence (orchestrator contract):
    engine.finalize()
    apply_domain_score_override(engine)   # from bob.domain_scores

After finalize() but before apply_domain_score_override(), engine.score
returns the raw deduction-based score.  The domain-averaged global score
is only available after apply_domain_score_override() sets the override.
```

Docstring de `ScoreEngine.set_global_score()` mise à jour :

```
Do not call this directly — use apply_domain_score_override(engine)
from bob.domain_scores, which computes the correct domain average.
The raw pre-override score remains accessible as engine._raw_score.
```

---

### Fix 4 — Plafond de domaine non appliqué si le score brut global est déjà sous le seuil (`bob/domain_scores.py`)

`compute_domain_scores()` calcule le score de chaque domaine en sommant les déductions de `engine.breakdown` qui lui correspondent. Lorsqu'un plafond se déclenche (ex. `firewall.inactive` → max 3/10), `finalize()` ajoute un delta de déduction dans `breakdown` **uniquement si** `_raw_score > cap.maximum`. Sur un système cumulant beaucoup de déductions (pare-feu + durcissement + …), le score brut global peut déjà être sous le seuil du plafond — le delta n'est jamais ajouté, le score du domaine cible reste à sa valeur brute pré-plafond (ex. 6/10 au lieu de 3/10 pour le pare-feu quand UFW est inactif). La note « Score plafonné à 3 » s'affiche quand même (elle lit `engine.cap_info` enregistré, indépendamment du déclenchement). Correction : `compute_domain_scores()` lit maintenant `engine.cap_info` et, si sa clé correspond à un domaine, applique directement le plafond sur le total de déductions de ce domaine. Le fix est idempotent. Trouvé sur une VM Ubuntu 26.04 avec UFW inactif et plusieurs problèmes de durcissement.

### Fix 5 — Check de règle orpheline manquant les règles UFW sans protocole (`bob/checks/firewall.py`)

`_check_orphan_rules()` analysait le champ « To » d'UFW avec `_PORT_PROTO_RE` qui exige un suffixe de protocole explicite (`/tcp` ou `/udp`). Une règle écrite en numéro de port nu — syntaxe UFW valide signifiant « appliquer à TCP et UDP » — produisait `m = None` et tombait dans `continue`. En pratique, `57621 ALLOW IN 192.168.1.0/24` (Spotify Connect) coexistait avec `41681/tcp ALLOW IN 192.168.1.0/24`. BOB signalait correctement `41681/tcp` comme règle orpheline mais ignorait silencieusement `57621`. Nouveau `_PORT_BARE_RE` gère ce cas de repli. Trouvé en exécutant l'outil sur une machine réelle.

### Fix 6 — Locale SSH : commande dupliquée dans le bloc « Que faire ? » (`bob/locales/fr.json`, `bob/locales/en.json`)

`ssh.not_active_detail` contenait la commande de remédiation (`"Activer avec : sudo systemctl enable --now ssh"`). Le moteur d'affichage rendant à la fois le `detail` et le `cmd` sous forme de lignes `→`, le bloc « Que faire ? » affichait deux fois la même commande. Le champ `detail` est destiné au contexte (pourquoi agir), pas à la commande (qui appartient à `cmd`). Corrigé par un texte explicatif sans commande : `"Le service est désactivé — activez-le si l'accès SSH est nécessaire."` Trouvé sur Kali Linux où SSH est installé mais intentionnellement arrêté.

### Tests d'invariants scoring (`tests/test_scoring.py`, `tests/test_domain_scores.py`)

Classes `TestScoringInvariants` ajoutées aux deux fichiers de test — 12 nouveaux tests pour les propriétés structurelles devant tenir quel que soit l'input. C'est la couche de tests de propriétés du pipeline de scoring, couvrant la monotonie, les bornes et la sémantique d'activation.

#### `tests/test_scoring.py` — `TestScoringInvariants` (+5)

Invariants du moteur de scoring : score plancher (0), plafond (MAX), monotonie des déductions, plafond supérieur sans effet, override domaine dans la plage.

#### `tests/test_domain_scores.py` — `TestScoringInvariants` (+7)

Points clés :

- **INFO-only → domaine inactif :** un finding `level=INFO` sans déduction ne marque pas le domaine comme « actif » pour la moyenne globale.
- **WARN/ALERT → domaine actif :** ces niveaux activent bien le domaine, même sans déduction associée.
- **Déduction seule active :** `add_deduction(key=...)` sans finding active quand même le domaine via le chemin déductions dans `active_domains_from_engine()`.
- **Moyenne globale bornée :** résultat de `compute_global_from_domains` toujours `≥ min(scores_actifs)` et `≤ max(scores_actifs)`.
- **Scores dans la plage :** `compute_domain_scores` produit toujours des valeurs dans `[0, MAX_SCORE]` pour chaque domaine.

Le test d'activation par déduction seule est particulièrement important : il confirme que `active_domains_from_engine()` vérifie à la fois le chemin findings (filtre WARN/ALERT) et le chemin déductions (sans filtre), et que cette asymétrie est intentionnelle.

### Tests

4261/4261 (+23 nouveaux, 2 mis à jour) :

#### `tests/test_domain_scores.py` — `TestEngineLevelDomainCap` (+6)

Six nouveaux cas dans une nouvelle classe couvrant le fix du plafond de domaine : plafond appliqué avec peu de déductions · plafond appliqué quand le score brut global est déjà sous seuil (delta absent du breakdown) · pas de sur-plafonnement si déjà au cap · score ne dépasse jamais le plafond · pas de saignement vers d'autres domaines · tous scores dans la plage.

#### `tests/test_firewall.py` — `TestOrphanRules` (+3)

Trois nouveaux cas dans la classe `TestOrphanRules` existante : règle bare-port signalée si rien en écoute · non signalée si TCP en écoute · non signalée si UDP en écoute.

#### `tests/test_manage_logs.py` — `TestStatFallback` (+2)

Régression pour le fix race condition `.stat()` de v0.2.1. Les boucles d'affichage mode texte dans `_run_manage_logs_plain()` avaient été mises à jour en v0.2.1 pour envelopper `.stat()` dans `try/except OSError` — mais aucun test ne couvrait le chemin de repli.

Un helper `_stat_raises_for_logs` est défini au niveau module (capturé avant tout run de test) qui lève `OSError` uniquement pour les fichiers `.log`, en déléguant au vrai `Path.stat` pour les répertoires. C'est nécessaire car `Path.exists()` de Python 3.12 appelle `self.stat()` en interne — un mock global casserait `exists()` sur les répertoires et ferait échouer les tests.

```python
_real_path_stat = Path.stat

def _stat_raises_for_logs(self, *, follow_symlinks=True):
    if self.suffix == ".log":
        raise OSError("race: file disappeared between scan and display")
    return _real_path_stat(self, follow_symlinks=follow_symlinks)
```

| Test | Couverture |
|------|------------|
| `test_cur_logs_stat_oserror_uses_fallback` | `.stat()` lève dans la boucle `cur_logs` → `"(0 "` et `"?"` dans la sortie |
| `test_extra_logs_stat_oserror_uses_fallback` | `.stat()` lève dans la boucle `extra_sections` → idem |

#### `tests/test_clamav.py` (2 mis à jour)

| Test | Avant | Après |
|------|-------|-------|
| `test_db_very_outdated_deducts_1` (était `_deducts_2`) | vérifiait `pts == 2` | vérifie `pts == 1` |
| `test_worst_case` | vérifiait total == 4 | vérifie total == 3 |

---

## [v0.2.1] — 02-05-2026

Hotfix défensif — 17 améliorations ciblées identifiées par un audit dual-agent (passes indépendantes par Claude et Copilot). Aucune nouvelle fonctionnalité, aucun changement de comportement, aucun nouveau test. 4238/4238 inchangés.

### `bob/manage_logs.py` — correction de crash : `.stat()` non protégé en mode texte

#### Problème

Les boucles d'affichage mode texte dans `_run_manage_logs_plain()` appelaient `f.stat()` directement :

```python
size_kb = max(1, f.stat().st_size // 1024)
mtime = _dt.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
```

Si un fichier log était supprimé entre le scan du répertoire et la boucle d'affichage (ex. : `logrotate` en parallèle), cela levait `OSError` et plantait `--manage-logs`. Le mode curses (lignes 792–796) avait déjà la protection correcte :

```python
try:
    size_kb = max(1, f.stat().st_size // 1024)
    mtime   = _dt.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
except OSError:
    size_kb, mtime = 0, "?"
```

#### Correction

Les deux boucles du chemin mode texte (`cur_logs` et `extra_sections`) enveloppent maintenant `.stat()` de façon identique au mode curses, avec `(0, "?")` comme valeurs de repli.

---

### Resserrement des gestionnaires d'exceptions — 8 emplacements

Tous les `except Exception` (qui capturent aussi les erreurs de programmation et compliquent le débogage) remplacés par les types d'exceptions spécifiques pouvant réellement être levées.

#### `bob/cis_refs.py` — `_load()`

Lit et parse un fichier JSON. Seuls échecs possibles : I/O (`OSError`) et JSON malformé (`json.JSONDecodeError`).

```python
# avant
except Exception:
    return {}

# après
except (OSError, json.JSONDecodeError):
    return {}
```

#### `bob/manage_logs.py` — `_get_extra_dirs()`

Parse une liste de chaînes encodée en JSON depuis la config utilisateur. Échecs : JSON malformé, types de valeurs inattendus.

```python
# avant
except Exception:
    return []

# après
except (json.JSONDecodeError, ValueError, TypeError):
    return []
```

#### `bob/manage_logs.py` + `bob/explain.py` + `bob/cron.py` — replis curses

Trois appels `curses.wrapper()` qui reviennent au mode texte en cas d'échec terminal. `curses.error` couvre tous les échecs d'initialisation et de rendu terminal ; `OSError` couvre les erreurs I/O niveau terminal.

```python
# avant (les trois sites)
except Exception:
    return _run_*_plain(...)

# après
except (curses.error, OSError):          # manage_logs.py, explain.py
    return _run_*_plain(...)

except (_curses.error, OSError):         # cron.py (curses importé comme _curses)
    return _run_*_plain(...)
```

#### `bob/checks/ssh.py` — parsing binaire des clés

`_rsa_bits_from_blob()` : décode du base64 et dépaquète un format binaire SSH. Échecs : base64 invalide (`binascii.Error`, sous-classe de `ValueError`) et struct malformé (`struct.error`).

```python
# avant
except Exception:
    return None

# après
except (struct.error, ValueError):
    return None
```

`_has_passphrase()` : décode des données base64 de clé OpenSSH. Seul `binascii.Error` (base64 invalide, sous-classe de `ValueError`) peut être levé dans le bloc try.

```python
# avant
except Exception:
    return None

# après
except (binascii.Error, ValueError):
    return None
```

`import binascii` ajouté en tête de `ssh.py`.

---

### Regex déplacées en module-level — 3 fichiers

Les patterns `re.compile()` définis dans les corps de fonctions — recompilés à chaque appel — déplacés en constantes module. Python ne met pas en cache les résultats de `re.compile()` appelés dans des fonctions.

#### `bob/checks/firewall.py`

```python
_OPEN_ANY_RE = re.compile(
    r"Anywhere(?:/\w+)?(?:\s+\(v6\))?\s+ALLOW\s+IN\s+Anywhere(?:/\w+)?(?:\s+\(v6\))?\s*$",
    re.IGNORECASE,
)
_ALLOW_IN_RE   = re.compile(r"\bALLOW\s+IN\b", re.IGNORECASE)
_PORT_PROTO_RE = re.compile(r"\b(\d{1,5}/(?:tcp|udp))\b", re.IGNORECASE)
```

`_check_open_any()` et `_check_orphan_rules()` mis à jour pour référencer les constantes module.

#### `bob/checks/cron_audit.py`

```python
_PATH_RE = re.compile(r"(/[^\s;|&<>]+\.sh)\b")
```

Déplacé depuis l'intérieur de `_find_world_writable_scripts()` vers le module, aux côtés du `_PIPE_TO_SHELL_RE` existant.

#### `bob/checks/firmware.py`

```python
_FLAT_SKIP_RE = re.compile(
    r"^(Update|Version|Summary|Description|Requires|Urgency|Remote|Size|"
    r"Flags|Status|GUID|Device|AppStream|Release|\[|WARNING|Error|\s)",
    re.IGNORECASE,
)
```

Déplacé depuis l'intérieur de `_parse_fwupd_updates()` vers le module, aux côtés du `_TREE_ITEM_RE` existant.

---

### `bob/cron.py` — regex email dédupliqué

`_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")` était défini identiquement dans trois fonctions séparées : `_select_emails_plain()` (ligne 325), `_curses_email_list_sub()` (ligne 1273), `_curses_email_store_sub()` (ligne 1398). Déplacé en constante module unique (ligne 20). Le même pattern existe indépendamment dans `bob/config.py` pour la validation de config ; les deux sont intentionnellement conservés, chaque module possédant sa propre contrainte.

---

### `bob/manage_logs.py` — helper `_resolve_path()` extrait

```python
def _resolve_path(raw: str, default: Path) -> Path:
    """Expand, resolve and return *raw* as a Path, or *default* if empty."""
    return Path(raw).expanduser().resolve() if raw else default
```

Le one-liner `Path(raw).expanduser().resolve() if raw else default` apparaissait à deux endroits : dans le `return` de `_prompt_path()` et dans le flux de changement de répertoire. Les deux appellent maintenant `_resolve_path()`. Le commentaire de sécurité (`resolve() normalise les composants ".."…`) est conservé au premier site d'appel.

---

### `bob/domain_scores.py` — accès direct aux attributs

`active_domains_from_engine()` et `compute_domain_scores()` utilisaient `getattr(engine, "findings", [])`, `getattr(finding, "key", None)` et `getattr(deduction, "points", 0)` comme gardes défensifs. `ScoreEngine.__init__` initialise toujours `findings`, `ignored_findings` et `breakdown` comme listes vides ; `Finding` et `Deduction` sont des dataclasses avec `key` et `points` comme champs obligatoires. Les `getattr` masquaient une dérive potentielle de l'API au lieu de la faire remonter. Remplacés par accès direct dans tout le fichier.

---

### `bob/recurrence.py` — log debug sur échec de chargement

```python
# avant
except (OSError, json.JSONDecodeError, ValueError):
    pass

# après
except (OSError, json.JSONDecodeError, ValueError) as exc:
    _log.debug("Failed to load recurrence data from %s: %s", src, exc)
```

`import logging` et `_log = logging.getLogger(__name__)` ajoutés. Les échecs restent non-fatals (le suivi de récurrence est best-effort) mais remontent désormais avec le niveau de log `--debug`.

---

### `bob/__main__.py` — logging des échecs webhook

```python
# avant
except Exception as _exc:  # noqa: BLE001
    print(f"Warning: webhook failed: {_exc}", file=sys.stderr)

# après
except Exception as _exc:  # noqa: BLE001
    _log.warning("Webhook failed: %s", _exc)
    print(f"Warning: webhook failed: {_exc}", file=sys.stderr)
```

`import logging` et `_log = logging.getLogger(__name__)` ajoutés. Les échecs webhook sont maintenant capturés par le système de logging en plus de l'affichage stderr visible par l'utilisateur.

---

### Tests

4238/4238 — aucun nouveau test, aucun changement de comportement. Tous les tests existants passent sans modification.

---

## [v0.2.0] — 01-05-2026

Cinq améliorations trouvées lors de l'analyse des premiers lancements sur Ubuntu 26.04 LTS et Debian 13.

### `bob/scoring.py` + `bob/domain_scores.py` — refonte du scoring

#### Problème

Le score global était calculé comme `10 − somme(toutes_les_déductions)`. Sur Debian 13 avec 8 déductions de −1 chacune, cela produisait 2/10 CRITIQUE alors que SSH, pare-feu, mises à jour et permissions fichiers étaient tous parfaits. Le score ne représentait pas la posture de sécurité réelle de la machine.

Deux problèmes supplémentaires :
- **Double pénalité sur un même outil** — rkhunter émettant `rootkit.db_outdated` et `rootkit.no_scan` déduisait 2 points du score global pour une seule décision de configuration.
- **Déconnexion score global / scores de domaine** — les scores de domaine étaient calculés indépendamment mais le score global n'en était pas dérivé, créant une contradiction dans la sortie.

#### Correction 1 — Plafond par outil dans `compute_domain_scores()`

Nouveau dict `_TOOL_CAPS` dans `domain_scores.py` :

```python
_TOOL_CAPS: dict[str, int] = {
    "rootkit":        1,   # rkhunter/chkrootkit — âge base + âge scan
    "clamav":         1,   # ClamAV — âge base + fréquence scan
    "file_integrity": 1,   # AIDE/Tripwire — présence + fraîcheur
}
```

Lors de l'accumulation des déductions par domaine dans `compute_domain_scores()`, chaque préfixe d'outil est plafonné à sa contribution maximale. Une deuxième déduction de `rootkit.*` quand le plafond est atteint contribue 0 point au score du domaine. Les préfixes sans plafond (`hardening.*`, `ssh.*`, etc.) s'accumulent normalement.

#### Correction 2 — Score global = moyenne des scores de domaine actifs

Nouvelle fonction `compute_global_from_domains(domain_scores, active_domains) -> int` dans `domain_scores.py` :

```python
active = [d for d in DOMAINS if d in active_domains and d in domain_scores]
return max(0, min(MAX_SCORE, round(total / len(active))))
```

Nouvelle fonction `apply_domain_score_override(engine)` appelle `compute_domain_scores`, `active_domains_from_engine` et `compute_global_from_domains`, puis appelle `engine.set_global_score()` avec le résultat.

Nouvelle méthode `ScoreEngine.set_global_score(score: int)` stocke la valeur domain-averaged dans `_global_override`. La property `score` retourne `_global_override` quand définie, avec repli sur `_raw_score` sinon. Le score brut interne n'est jamais modifié — disponible à `engine._raw_score` pour le débogage.

`apply_domain_score_override(engine)` est appelé immédiatement après `engine.finalize()` dans `bob/__main__.py` et `bob/watch.py`.

#### Effet

Cas de référence Debian 13 (8 déductions, tous les autres domaines sains) :
- Avant : 2/10 CRITIQUE (somme brute)
- Après : 6/10 (hardening=4, disk=9, moyenne des 2 domaines actifs dans le scénario de test ; 9/10 en utilisation réelle avec SSH/pare-feu/mises à jour actifs à 10/10)

### `bob/cron.py` — détection MTA (`_detect_mta()`)

#### Problème

L'assistant cron vérifiait `shutil.which("mail")` et avertissait `'mail' non disponible — installez mailutils`. La livraison des emails dans `report_markdown.py` utilise `sendmail -t -f`, pas `mail`. La vérification testait le mauvais binaire et recommandait un paquet inutile.

#### Correction

Nouveau helper `_detect_mta() -> tuple[bool, str]` :

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

Les deux points d'appel dans `_run_install_cron_plain` et `_run_install_cron_curses` utilisent désormais `_detect_mta()`. Quand un email est configuré :
- MTA trouvé : `✔ Transport mail : Postfix (sendmail disponible — les notifications seront envoyées)`
- MTA absent : `⚠ sendmail introuvable — les emails de notification ne seront pas envoyés. Installez : sudo apt install postfix  ou  sudo apt install msmtp-mta`

Les clés de locale `mail_missing` remplacées par `mta_missing` et `mta_found` dans `bob/locales/en.json` et `bob/locales/fr.json`.

### `bob/checks/kernel_modules.py` — faux positif kernel `-unsigned` Debian

#### Problème

Sur Debian avec Secure Boot activé, apt installe à la fois :
- `linux-image-6.12.74+deb13+1-amd64` — noyau signé (démarré quand Secure Boot est actif)
- `linux-image-6.12.74+deb13+1-amd64-unsigned` — variante non signée (même version, paquet différent)

`_check_installed_kernels()` triait tous les noyaux installés par `_kernel_sort_key()`. Les deux variantes produisent la même clé de tri numérique `(6, 12, 74, 0)`. Le tri stable de Python retombe alors sur l'ordre lexicographique, plaçant `-amd64-unsigned` après `-amd64`. `most_recent` était défini comme la variante unsigned, faisant évaluer `running != most_recent` à `True` — déclenchant un faux avertissement de redémarrage.

#### Correction

Nouveau helper `_strip_unsigned(version: str) -> str` :

```python
def _strip_unsigned(version: str) -> str:
    return version[:-len("-unsigned")] if version.endswith("-unsigned") else version
```

`reboot_pending` compare désormais les versions sans le suffixe :

```python
reboot_pending = running in kernels and _strip_unsigned(running) != _strip_unsigned(most_recent)
```

Une véritable différence de version (ex. `6.12.63+deb13-amd64` en cours d'exécution alors que `6.12.74+deb13+1-amd64` est installé) déclenche toujours correctement l'avertissement de redémarrage.

### Tests

- `tests/test_kernel_modules.py` — +6 tests :
  - `TestKernelRebootPending.test_no_reboot_pending_debian_signed_plus_unsigned_same_version`
  - `TestKernelRebootPending.test_reboot_still_pending_when_genuinely_newer_debian_kernel`
  - `TestStripUnsigned` — 4 tests unitaires pour `_strip_unsigned()`
- `tests/test_cron.py` — +6 tests dans `TestDetectMta` : sans sendmail, Postfix (via fichier config), Exim, msmtp, ssmtp, MTA inconnu
- `tests/test_scoring.py` — +6 tests dans `TestSetGlobalScore` : override remplace le brut, pas d'override par défaut, clamp au-dessus du max, clamp sous zéro, niveau reflète l'override, score brut inchangé
- `tests/test_domain_scores.py` — +14 tests :
  - `TestToolCaps` (7 tests) — rootkit/clamav/file_integrity plafonné à 1 ; préfixes sans plafond s'accumulent ; plafonds ne débordent pas entre outils ; déduction partielle respecte le plafond
  - `TestComputeGlobalFromDomains` (4 tests) — moyenne, domaines vides, clamp max, clamp zéro
  - `TestApplyDomainScoreOverride` (3 tests) — override appliqué, plage valide, scénario Debian 13
- **Total : 4238 tests** (4206 → 4238, +32)

### `bob/checks/logs.py` — dominance IoT dans les logs : WARN −1 pt

#### Problème

Quand une seule IP privée représentait ≥ 70 % du trafic UFW bloqué sur ≥ 50 entrées, BOB émettait un finding `INFO` sans déduction de score. La fonctionnalité était documentée comme WARN −1 pt dans README_TECH.md, mais l'implémentation appelait `result.info()` sans `add_deduction()` — la déduction n'était jamais appliquée.

Découvert lors du premier test local sur `so6desktop` : `192.168.1.50` représentait 2267/2415 blocages (93 %) sans WARN ni déduction émis.

#### Correction

`bob/checks/logs.py` :
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

Nouvelle clé `deduction.local_dominance` ajoutée dans `bob/locales/en.json` et `bob/locales/fr.json`.

Trois tests existants dans `tests/test_logs.py` corrigés pour vérifier le comportement désormais correct :
- `test_check_logs_emits_warn_finding` (était `test_check_logs_emits_info_finding`)
- `test_finding_is_warn_level` (était `test_finding_is_info_level`)
- `test_score_deduction_one_point` (était `test_no_score_deduction`)

Total des tests inchangé : 4238.

### `bob/output.py` — bannière ASCII orange

L'art ASCII `BOB` affiché dans la bannière terminal est maintenant rendu en orange bold (`_c.orange_bold` = `\033[1;38;5;208m`). Les caractères de bordure (`║`, `╔`, `╠`, `╚`) conservent leur couleur bleu bold existante. Aucun impact sur les formats de sortie ni sur les fichiers de log — rendu terminal uniquement.

---

## [v0.1.1] — 29-04-2026

Hotfix. Trois corrections ciblées trouvées lors des premiers lancements sur Ubuntu 26.04 LTS et Debian 13.

### Corrections

#### `bob/checks/firmware.py` — parser fwupd 1.9+ format arbre

`fwupdmgr get-updates` a changé son format de sortie dans fwupd 1.9+ (livré avec Ubuntu 26.04 LTS). L'ancien parser supposait des noms d'appareils en colonne 0 avec les métadonnées indentées ; le nouveau format utilise une structure en arbre :

```
QEMU Ubuntu 24.04 PC (Q35 + ICH9, 2009)
│
├─UEFI CA:
│   Nouvelle version : 2024.01
│
└─QEMU DVD-ROM:
    Nouvelle version : 2.5
```

L'ancien `_parse_fwupd_updates()` capturait `│` et `├─UEFI CA:` comme noms d'appareils, produisant une sortie corrompue : `10 mise(s) à jour firmware en attente : QEMU Ubuntu 24.04 PC (Q35 + ICH9, 2009), │, ├─UEFI CA: (+7)`.

Correction : détection automatique du format arbre (présence de lignes `├─`/`└─`) ; en mode arbre, les noms d'appareils sont extraits uniquement depuis les lignes `├─`/`└─` en supprimant le préfixe et les deux-points finaux ; les lignes `│` et les lignes de conteneur parent sont ignorées. Le format plat reste inchangé.

Nouvelle constante de module : `_TREE_ITEM_RE = re.compile(r"^[├└]─\s*")`.

#### `bob/__main__.py` — message d'erreur `--install-completion`

Lorsque `bob --install-completion` est lancé sans root, le message d'erreur affichait la bonne commande avec le chemin complet (`sudo /chemin/vers/bob --install-completion`), mais les utilisateurs tapaient naturellement `sudo bob --install-completion` à la place, ce qui échoue car le PATH restreint de sudo n'inclut pas le `~/.local/bin` de pipx.

Le nouveau message explique explicitement que `sudo bob` ne fonctionnera pas (restriction PATH pipx) et invite à copier-coller la commande exacte affichée.

#### `bob/locales/en.json`, `bob/locales/fr.json` — en-tête de colonne du panorama des services

`services.panorama.header_ufw` : `"UFW"` → `"SCOPE"` (EN) / `"PORTÉE"` (FR).

La colonne utilise `Exposure.OPEN_WORLD` pour déterminer l'indicateur — elle reflète si un service a une exposition de portée internet, pas si une règle UFW active le couvre. Avec UFW inactif, les services à portée LAN (Avahi, CUPS) affichaient correctement `✔` mais le label `UFW` suggérait une protection pare-feu active. Le nouveau label élimine cette ambiguïté.

### Tests

- `tests/test_firmware.py` — 4 nouveaux tests de régression couvrant le parser format arbre :
  - `test_tree_format_extracts_device_names` — les lignes `├─`/`└─` produisent les bons noms d'appareils
  - `test_tree_format_excludes_container_line` — le conteneur parent n'est pas capturé
  - `test_tree_format_excludes_tree_connectors` — les caractères `│`, `├`, `└` sont absents des résultats
  - `test_tree_format_strips_trailing_colon` — les noms extraits de `├─Nom:` ne conservent pas les deux-points
- **Total : 4206 tests** (4202 → 4206, +4)

---

## [v0.1.0] — 2026-04-26

Version initiale de BOB — Bodyguard Of Bits.

### Architecture

- **Module** `bob/` — package Python ; point d'entrée CLI `bob` via `bob.__main__:main`
- **46 vérifications** organisées en 9 domaines de sécurité ; chaque vérification produit des objets `Finding` typés consommés par le moteur de scoring
- **Moteur de scoring** (`bob/scoring.py`) — déductions pondérées par résultat, clampées 0–10 ; 5 sous-scores par domaine (firewall, ssh, hardening, updates, file_perms)
- **i18n** (`bob/i18n.py`, `bob/locales/en.json`, `bob/locales/fr.json`) — toutes les chaînes utilisateur externalisées ; `--french` / `-d` bascule la locale au runtime
- **Profils d'audit** (`bob/profiles.py`, `bob/data/profiles/`) — `server`, `workstation`, `desktop`, `docker` ; chaque profil déclare des surcharges de sévérité et des sections ignorées
- **API plugin** (`bob/plugin_checks.py`, `bob/registry.py`) — vérifications personnalisées via `~/.config/bob/checks.d/` ; définitions de services personnalisées via `~/.config/bob/services.d/`

### Vérifications de sécurité

#### Pare-feu
- `bob/checks/firewall.py` — règles UFW : règles dupliquées, règles open-any, couverture IPv6, conscience de la politique par défaut deny
- `bob/checks/iptables_nftables.py` — CHECK 46 : audit iptables/nftables quand UFW est inactif ; politique INPUT/FORWARD/OUTPUT ; détection conntrack ; analyse du ruleset nftables
- `bob/checks/ipv6.py` — cohérence IPv6 entre les règles UFW et sysctl
- `bob/checks/firewall_stack.py` — détection de la pile pare-feu (UFW/iptables/nftables/aucun) ; pile active affichée dans le banner
- `bob/checks/ports.py` — analyse d'exposition des ports : public vs LAN vs loopback ; identification des services ; filtrage des ports éphémères

#### SSH
- `bob/checks/ssh.py` — PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords, X11Forwarding, MaxAuthTries, ClientAliveInterval, UsePAM, AllowTcpForwarding, qualité des algorithmes de clés, ListenAddress, Banner

#### Durcissement noyau
- `bob/checks/kernel_hardening.py` — 20+ paramètres sysctl (net.ipv4/ipv6, fs.*, kernel.*) ; randomize_va_space, dmesg_restrict, kptr_restrict, ptrace_scope, etc.
- `bob/checks/kernel_modules.py` — modules filesystem et réseau à risque (cramfs, freevxfs, jffs2, hfs, udf, dccp, sctp, rds, tipc)
- `bob/checks/secure_boot.py` — état du Secure Boot via mokutil/efibootmgr
- `bob/checks/firmware.py` — mises à jour fwupd en attente ; présence des paquets microcode

#### Services
- `bob/checks/services.py` — 32 services connus avec classification du risque ; écoute sur les ports attendus ; contexte de risque affiché par service actif
- `bob/checks/services_state.py` — audit des services systemd activés+actifs ; CRITICAL/HIGH installé-mais-inactif → avertissement
- `bob/checks/docker.py` — détection de l'installation Docker ; contournement pare-feu UFW via la chaîne iptables DOCKER
- `bob/checks/docker_audit.py` — durcissement daemon.json ; conteneurs privilégiés ; network/pid/ipc hôte ; montages sensibles ; no-new-privileges
- `bob/checks/smtp.py` — exposition serveur SMTP ; inet_interfaces ; risque open relay

#### Permissions fichiers
- `bob/checks/file_perms.py` — fichiers world-writable ; permissions /etc/passwd /etc/shadow /etc/sudoers
- `bob/checks/suid_audit.py` — audit SUID/SGID avec liste blanche ; racines ciblées pour la performance

#### Comptes utilisateurs
- `bob/checks/user_accounts.py` — comptes expirés (UID≥1000) ; comptes verrouillés avec connexions récentes
- `bob/checks/password_policy.py` — /etc/login.defs (PASS_MAX_DAYS, PASS_MIN_DAYS, PASS_WARN_AGE) ; PAM pam_cracklib/pam_pwquality ; historique de mots de passe PAM
- `bob/checks/umask.py` — umask système (/etc/profile, /etc/bash.bashrc, /etc/login.defs)

#### Système
- `bob/checks/updates.py` — mises à jour de sécurité apt en attente (−2 flat) ; mises à jour régulières (INFO) ; unattended-upgrades compound (−1) ; vérification apt du noyau
- `bob/checks/logs.py` — niveau de journalisation UFW (off/low/medium/high/full)
- `bob/checks/log_rotation.py` — configuration logrotate ; taille /var/log/ufw.log ; rétention des logs
- `bob/checks/auth_log.py` — comptage des échecs de connexion depuis auth.log/journald ; patterns d'échecs répétés
- `bob/checks/ntp.py` — état de synchronisation NTP (systemd-timesyncd / chrony / ntpd)
- `bob/checks/fail2ban.py` — Fail2ban actif ; jail sshd activé
- `bob/checks/rootkit.py` — présence et âge du dernier scan rkhunter / chkrootkit
- `bob/checks/auditd.py` — auditd actif ; règles d'audit présentes ; règles clés (commandes privilégiées, modifications sudoers)
- `bob/checks/file_integrity.py` — présence et dernière exécution AIDE / Tripwire
- `bob/checks/clamav.py` — paquet ClamAV ; âge de la base freshclam ; âge du dernier scan
- `bob/checks/mac_policy.py` — AppArmor (profils chargés, enforce vs complain) / SELinux (enforcing vs permissive)
- `bob/checks/backup.py` — détection d'une solution de sauvegarde (restic, duplicati, borgbackup, rsync cron, timeshift)
- `bob/checks/disk.py` — santé SMART (smartctl) ; utilisation des partitions ; niveau d'usure NVMe
- `bob/checks/memory.py` — swap présent ; usure swap SSD ; réglage swappiness
- `bob/checks/ssl_certs.py` — scan d'expiration des certificats TLS/SSL (≤30 jours → WARN, ≤7 → ALERT)
- `bob/checks/systemd_timers.py` — timers système actifs ; timers manqués ; options de sécurité des unités timer
- `bob/checks/desktop_apps.py` — applications desktop installées (navigateurs, messagerie, etc.) sur profil serveur
- `bob/checks/samba.py` — durcissement Samba (map to guest, null passwords, min protocol, signing)
- `bob/checks/cron_audit.py` — scripts cron world-writable ; patterns pipe-to-shell ; format /etc/cron.d
- `bob/checks/ddns.py` — activité client DDNS (ddclient) ; reflété dans l'analyse d'exposition internet

#### Réseau
- `bob/sysinfo.py` — détection IP publique (3 fournisseurs : ipify → ifconfig.me → icanhazip) ; adresse IPv6 publique ; contexte réseau (serveur/LAN/CGNAT/VPN) ; GeoIP2 optionnel
- `bob/checks/network_context.py` — classification du type de réseau ; contexte d'exposition affiché par résultat
- `bob/checks/virtualization.py` — détection de virtualisation (KVM/VirtualBox/VMware/LXC/Docker)

### Mapping des benchmarks CIS

- `bob/cis_refs.json` — 133 entrées : `{"ref": "...", "code": "CIS:X.Y.Z"|null}`
  - 99 benchmarks CIS Ubuntu 22.04 (avec `code: "CIS:X.Y.Z"`)
  - 4 benchmarks CIS Docker (avec `code: "CIS Docker:X.Y"`)
  - 34 entrées bonnes pratiques (avec `code: null`)
- `bob/cis_refs.py` — `get_cis_ref(key)` / `get_cis_code(key)` — `_load()` avec `lru_cache(maxsize=1)`
- `bob/display.py` — `[CIS:X.Y.Z]` injecté en ligne dans la boîte de synthèse par résultat ; référence complète en mode `--verbose`
- `bob/explain.py` — mode TUI et clé directe `--explain CLÉ` ; appelle `get_cis_ref()` directement

### Sortie et formatage

- `bob/output.py` — sortie terminal colorée ; boîte de synthèse ; graphique en barres des scores par domaine ; panorama des services
- `bob/display.py` — rendu des lignes de résultats ; injection du code CIS ; couleur du score ; qualificateurs de portée (`[CRITIQUE • INTERNET]`)
- `bob/json_output.py` — `--format=json` / `--json`
- `bob/csv_output.py` — `--format=csv`
- `bob/markdown_output.py` — `--format=markdown`
- `bob/report_markdown.py` — rapport markdown complet
- `bob/html_output.py` — `--html` rapport HTML autonome

### Automatisation et planification

- `bob/cron.py` — assistant curses `--install-cron` ; TUI `--manage-cron` ; jobs nommés (`/etc/cron.d/bob-{nom}`) ; notification email si code de sortie > 0 ; détection des crons legacy
- `bob/manage_logs.py` — TUI `--manage-logs` ; gestion du répertoire de logs ; sparkline d'historique des scores
- `bob/webhook.py` — webhook JSON générique + Slack (détecté automatiquement) ; non-fatal ; timestamps UTC ; scores par domaine inclus
- `bob/history.py` — historique des scores ajouté dans `~/.config/bob/history.jsonl` ; sparkline `--history`
- `bob/domain_scores.py` — scores 0–10 sur 5 domaines ; graphique en barres ; inclus dans la sortie JSON/webhook
- `bob/watch.py` — boucle de polling `--watch[=N]` ; relance l'audit complet toutes les N secondes (60 par défaut)
- `bob/compare.py` — diff de baseline `--diff` ; affichage delta uniquement ; baseline dans `~/.config/bob/last_baseline.json`
- `bob/recurrence.py` — tracker de résultats récurrents ; comptage des apparitions consécutives par clé

### CLI et configuration

- `bob/cli.py` — analyseur d'arguments ; 7 sections ; options courtes (-V -v -d -j -C -p -e -D -w -o) ; `--check`/`--skip` ; `--format` ; `--output-dir` ; `--target` ; `--min-level`
- `bob/completion.py` — `--install-completion` ; script de complétion bash dans `/etc/bash_completion.d/bob`
- `bob/config.py` — store persistant clé=valeur dans `~/.config/bob/config.conf`
- `bob/ignore.py` — `--ignore`/`--show-ignored` ; `~/.config/bob/ignore.yml`
- `bob/fixes.py` — UI dry-run `--fix` ; exécution `--apply`

### Tests

4200 tests répartis dans 65 fichiers de tests.

| Fichier | Couverture |
|---------|-----------|
| `test_cis_refs.py` | `cis_refs.py` / `cis_refs.json` — 39 tests |
| `test_iptables_nftables.py` | CHECK 46 — iptables/nftables |
| `test_firewall.py` | Audit des règles UFW |
| `test_ssh.py` | Vérifications de configuration SSH |
| `test_hardening.py` | Sysctl durcissement noyau |
| `test_kernel_modules.py` | Audit des modules noyau |
| `test_services.py` | Registre de services + risque |
| `test_services_state.py` | Audit de l'état des services |
| `test_docker.py` · `test_docker_audit.py` | Vérifications Docker |
| `test_ports.py` · `test_exposure.py` | Exposition des ports |
| `test_scoring.py` · `test_domain_scores.py` | Moteur de scoring |
| `test_explain.py` · `test_display_explain_hint.py` | TUI --explain |
| `test_cli.py` · `test_exit_codes.py` | CLI + codes de sortie |
| `tests/helpers.py` | Utilitaires de test partagés |
| *(+ 50 fichiers de tests supplémentaires)* | Couverture complète de tous les modules |
