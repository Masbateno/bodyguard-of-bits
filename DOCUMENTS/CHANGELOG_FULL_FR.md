*[Read in English](CHANGELOG_FULL.md)* · *[TL;DR](../CHANGELOG_FR.md)*

# BOB — Bodyguard Of Bits — Journal des modifications

Toutes les modifications notables du projet sont documentées ici.

---

## [v0.4.8] — 21-05-2026

**Passe d'audit code-quality 4** — réalisée par un sub-agent `general-purpose` dispatché après le reset du quota mensuel org, briefé avec `DOCUMENTS/SNAPSHOT.md` comme cartographie primaire. L'agent a lancé 4 chasses de patterns de bugs distincts (champs dataclass morts, helpers réinventés, timeouts incohérents, code mort post-refactor) et a retourné **4 IMPORTANT + 5 MINOR + 3 SUGGESTION findings**. Tous corrigés dans cette release, bundlés avec 6 améliorations pyproject.toml queueées depuis v0.4.7. 4499/4499 tests passent.

### I4 — fichiers de log `sudo bob -d` appartenaient à root (seul bug observable utilisateur)

**Reproduit** : n'importe quel `sudo bob -d` sur Linux. Le rapport détaillé à `~/.local/share/bob/logs/bob_YYYYMMDD_HHMMSS.log` était créé en mode `0o600` (correct — output confidentiel) mais avec ownership `root:root` parce que le syscall `open()` se passe dans le contexte sudo. L'utilisateur réel invocateur ne pouvait ni lire ni supprimer ses propres rapports après coup. Idem pour le répertoire parent `logs/` à sa première création via `mkdir(parents=True)`.

**Pourquoi ça a survécu 4 audits** : BOB a un pattern chown-back bien établi via `bob.sysinfo::chown_to_sudo_user(path)` — un thin wrapper autour de `os.chown(path, pw_uid, pw_gid)` résolu depuis `$SUDO_USER`, avec un no-op silencieux quand pas sous sudo. Le pattern était correctement appliqué à **7 modules** qui écrivent dans `~/.config/bob/` (`config.py`, `history.py`, `ignore.py`, `compare.py`, `recurrence.py`, `profiles.py`, `registry.py`) — mais jamais branché pour les deux modules qui écrivent dans `~/.local/share/bob/logs/`. L'omission ne se manifeste qu'au runtime via "permission denied" quand l'utilisateur essaie de `cat`/`rm` son rapport.

**Fix** : `bob/report.py::AuditReport.__init__` appelle `chown_to_sudo_user(path)` juste après le `os.open(..., 0o600)`. `bob/manage_logs.py::get_or_prompt_log_dir` appelle `chown_to_sudo_user(d)` après chaque `d.mkdir(parents=True, exist_ok=True)` (4 branches : `--output-dir`, config sauvée, non-interactif, interactif).

Le fix est non-invasif : zéro impact hors sudo (pas de `SUDO_USER` → early return).

### I1-I3 + M4-M5 — champs dataclass morts purgés

Huit champs dataclass populés par `from_system()` (i.e. faisant du vrai travail I/O à chaque audit) mais jamais lus par aucun consumer. Même classe de bug que le fix v0.4.3 C1 qui avait retiré 5 attrs morts de `HardeningSnapshot` causant des crashes `--json-full`.

| Check / dataclass | Champ(s) retiré(s) |
|---|---|
| `SSHSnapshot` | `config_source_files` (populé par walker récursif Include sshd_config ; le paramètre `sources` de `_parse_config_file()` est aussi dropped) |
| `FirewallStatus` | `ipv4_rules_count` + `ipv6_rules_count` (deux counters calculés à chaque audit via `sum(1 for ln in ...)` ; seuls consumers étaient les fixtures de tests) |
| `SambaSnapshot` | `min_protocol` (capturé depuis `min protocol` smb.conf ; seul `smb1_enabled` dérivé est consommé) |
| `ClamAVSnapshot` | `last_scan_log_path` + `db_path` (`_find_last_scan_date()` retournait un tuple mais seul `date` était utilisé ; simplifié pour retourner `Optional[str]`) |
| `SecureBootSnapshot` | `method` (détection method interne, "mokutil"/"efivars"/"bootctl" ; seul `state` est consommé) |

Tests mis à jour pour ne plus passer les kwargs supprimés. `test_default_method_is_none` dans `test_secure_boot.py` retiré (testait juste l'existence du champ). Net : -1 test.

### M1 — cohérence `_C_LOCALE_ENV`

Trois sites subprocess by-passaient la convention `env=_C_LOCALE_ENV` :

| Fichier | Ligne | Commande |
|---|---|---|
| `bob/checks/desktop_apps.py` | 111 | `ps -eo comm` |
| `bob/checks/smtp.py` | 58 | `ps -eo comm` |
| `bob/checks/smtp.py` | 102 | `ss -tlnp` / `netstat -tlnp` |

Aujourd'hui les sorties se trouvent indépendantes de la locale sur toutes les distros ciblées, donc le bypass est bénin. Mais la convention existe pour une raison — un futur `ss` qui localiserait "LISTEN" ou `ps` qui localiserait ses headers casserait silencieusement la détection dans ces checks pendant que tous les autres checks de BOB continueraient de fonctionner. Même leçon v0.4.3 strptime, appliquée préemptivement. Corrigé via `env=_C_LOCALE_ENV` sur les 3 sites.

### M3 — `log_rotation._service_active` inliné via `_run`

La fonction faisait 12 lignes de `subprocess.run(["systemctl", "is-active", name], ...)` + handling d'exception + `.stdout.strip() == "active"`. Le même pattern était déjà implémenté en one-liner via `_run()` dans `clamav.py`, `fail2ban.py`, `auditd.py`, `ssh.py`. Remplacé par `return _run("systemctl", "is-active", name, timeout=5).strip() == "active"`. Les imports locaux `subprocess` et `_C_LOCALE_ENV` devenus inutiles après le nettoyage — aussi retirés.

### M2 + S2 — dédoublonnement gestion cron (avec parité NOTIFY_EMAIL legacy)

`bob/cron.py::edit_cron_schedule` (wizard plain-text) et `bob/tui/cron.py::_apply_cron_schedule` (curses TUI) dupliquaient la même logique atomic-write + regex. Idem pour `edit_cron_email` (plain) vs `_apply_cron_email_str` (curses). La branche curses utilisait `r"^NOTIFY_EMAILS=.*$"` (force la forme S-suffixée moderne), tandis que la branche plain utilisait `r"^NOTIFY_EMAILS?=.*$"` (le `?` rend le S optionnel, supportant les cron files BOB pré-v0.3 qui écrivaient `NOTIFY_EMAIL=` sans le S). Résultat net : les users migrant d'une entrée cron pré-v0.3 pouvaient éditer leur email de notification via le wizard plain mais pas via la TUI curses — inconsistance UX silencieuse.

**Fix** : `apply_cron_schedule(entry, schedule_expr) -> str` et `apply_cron_email(entry, new_email) -> tuple[str, int]` promus en helpers publics dans `bob/cron.py`. `bob/tui/cron.py` les importe et expose des wrappers fins sous les noms `_apply_*` originaux pour les call sites existants (délégation d'une ligne chacun). La regex legacy `NOTIFY_EMAILS?=` est maintenant l'unique source de vérité pour les deux branches.

### S1 — fenêtre auth_log 90 jours documentée comme intentionnelle

`bob/checks/auth_log.py::_read_auth_from_journald` hardcode `max_days: int = 90` pour l'historique d'authentification SSH via `journalctl -t sshd --since=...`. L'audit a flaggé l'asymétrie avec le flag CLI `--log-days` (default 7) qui contrôle l'analyse des logs UFW dans `bob/checks/logs.py`. Investigation : c'est **intentionnel** et les deux fenêtres ont des sémantiques différentes.

Les logs UFW sont bruyants à chaque tentative de connexion — une fenêtre de 7 jours garde la table top-IPs / brute-force lisible et évite d'enterrer les vrais signaux. Les tentatives brute-force SSH peuvent être lentes et sporadiques sur plusieurs semaines ou mois (surtout contre un SSH hardenisé qui auto-ban après N essais — l'attaquant rotate ses IPs). Une fenêtre de 90 jours attrape ce signal long-tail. Documenté dans le docstring de la fonction pour que les audits futurs ne le re-flaggent pas comme inconsistance.

### S3 — `SCORE_BAR_WIDTH` exporté depuis `bob.output`

`_BAR_WIDTH = 10` était dupliqué en constante module-level dans `bob/breakdown.py`, `bob/domain_scores.py`, et `bob/display.py`. Les deux premiers sont des largeurs de barres de score (unité : score, range 0-10) ; le troisième est la largeur de barre disque-pourcent (unité : pourcentage, range 0-100) et est indépendant.

**Fix** : `SCORE_BAR_WIDTH = 10` promu depuis le `_SCORE_BAR_WIDTH` privé déjà utilisé par `output.score_bar()` (introduit dans l'harmonisation des jauges de v0.4.7). `breakdown.py` et `domain_scores.py` font maintenant `from bob.output import SCORE_BAR_WIDTH as _BAR_WIDTH`. `display.py::_BAR_WIDTH` laissé seul — même valeur numérique, unité sémantique différente, coïncidemment égale.

### Hardening pyproject.toml (queué depuis v0.4.7, appliqué ici)

Pendant la prep de v0.4.7 un audit exhaustif du pyproject.toml avait identifié 6 améliorations différées pour éviter de mélanger la plumberie release avec des changements structurels. Toutes appliquées en v0.4.8 plus un bonus :

1. **`Development Status :: 4 - Beta` → `5 - Production/Stable`**. 4499 tests, 7 distros CI, hardware production audité, 17+ releases PyPI depuis v0.1.0, contracts gelés. "Beta" suggérait "may have breaking changes within minor versions" — ce qui n'est plus vrai depuis v0.4.0.

2. **Champs `authors` + `maintainers` ajoutés**. PyPI affichait "Author: UNKNOWN" parce que les metadata PEP 621 n'avaient pas d'info auteur. Maintenant `pyproject.toml` porte l'attribution canonique.

3. **`[project.optional-dependencies] geoip = ["geoip2>=4.0"]`**. La feature de geolocation IP dans `bob/checks/logs.py` fait `try: import geoip2.database` avec fallback silencieux. La dépendance était auparavant installée via `pipx inject bodyguard-of-bits geoip2` — clunky. Maintenant les users peuvent `pipx install "bodyguard-of-bits[geoip]"` en une seule étape.

4. **`wheel` retiré de `build-system.requires`**. Depuis setuptools 70, `setuptools.build_meta` auto-resolve wheel — le lister explicitement est redondant et ralentit légèrement la préparation de l'env de build dans les builds PEP 517 isolés.

5. **URLs `Source` + `Documentation` ajoutées** à `[project.urls]`. PyPI affiche des icônes spéciales pour ces labels d'URL spécifiques.

6. **`dependencies = []` explicite** avec commentaire "Zero runtime deps — preserve at all costs". PEP 621 rend `dependencies` implicite si manquant, mais l'expliciter donne du poids à la policy.

**Bonus** : `[tool.setuptools.packages.find]::include = ["bob", "bob.checks", "bob.tui"]` (liste explicite) remplace le glob `["bob*"]` précédent. La forme glob inclurait n'importe quel futur répertoire top-level `bob_*` dans le wheel (e.g. un `bob_tmp/` accidentel d'une session de debug). L'explicite est plus défensif.

### Tests

4499/4499 passent — net -1 vs les 4500 de v0.4.7. Le test retiré est `tests/test_secure_boot.py::TestSecureBootSnapshot::test_default_method_is_none` qui assertait juste l'existence du champ `SecureBootSnapshot.method` (qui n'existe plus). Aucun test ne dépendait des autres champs dataclass retirés au-delà des kwargs de fixture — ceux-là ont été nettoyés.

---

## [v0.4.7] — 21-05-2026

**Release de maintenance** — passe d'audit cross-documentation, harmonisation cosmétique UI, refonte de la bash completion et automatisation de la création de release. Aucun changement de comportement dans le pipeline d'audit ; 4500/4500 tests inchangés.

### Audit cross-documentation (24 corrections sur 8 fichiers)

Entre v0.4.6 et v0.4.7 un audit exhaustif a rattrapé les claims qui avaient dérivé entre l'état réel du code et les docs user-facing. Aucun n'est un bug de *code* — ce sont des bugs documentaires qui auraient induit les utilisateurs en erreur en lisant les docs pour anticiper le comportement de l'outil.

#### `README.md` + `README_FR.md` (2 × 2 = 4 fixes)

**1. "9 domaines" → "7 domaines de score"** (lignes 7 et 97). Le "9 domaines" était le compte initial v0.1.0 (CHANGELOG mentionne "46 vérifications · 9 domaines" pour v0.1.0). Le moteur de scoring a été refactorisé en v0.2.x pour consolider en 7 domaines de score (`ssh`, `samba`, `file_perms`, `updates`, `hardening`, `disk`, `firewall`), mais les bannières README et le heading section disaient toujours "9 domaines" jusqu'à v0.4.6 — une dérive doc sur 4 versions mineures.

**2. Tableau de profils réécrit**. L'ancien tableau listait un profil `docker` qui **n'existe pas** (le vrai profil est `container` ; un utilisateur tapant `bob --profile=docker` obtiendrait un warning "Profile 'docker' not found — using default (server)") et inversait la relation `desktop` / `workstation`. En réalité, `desktop.conf` est le profil substantif (étend `server`, 11 overrides) et `workstation` est un alias de rétrocompatibilité que le loader réécrit en `desktop` (`bob/profiles.py::load_profile` fait `if name == "workstation": name = "desktop"`). Le fichier `workstation.conf` est shipped en package-data mais n'atteint jamais le loader. Tableau corrigé avec 4 lignes (`server`, `desktop`, `workstation` comme alias, `container`) et relations exactes.

#### `DOCUMENTS/README_TECH.md` + FR (2 × 2 = 4 fixes)

Même dérive "9 domaines" (ligne 12) → "7 domaines de score". Plus une seconde dérive ligne 79 : "17 clés avec sections par profil" → "19 clés". Vérifié en parcourant `bob/locales/en.json::explain.{key}.server.why`. Aussi "À partir de v0.4.6" → "À partir de v0.4.7" dans la section sur le support Python.

#### `DOCUMENTS/README_DEV.md` + FR (2 × 2 = 4 fixes)

Même "17 clés × 3 profils" → "19 clés × 3 profils" (ligne 57). "Le fichier contient ~1500 clés" → "exactement 1401 clés" (ligne 469). Le "~1500" était une approximation vague qui dérivait ; le compte réel est précis et testable : `en.json` et `fr.json` ont tous deux 1401 clés avec parité stricte (enforced par `tests/test_locale_coverage.py::TestLocaleCoverage`).

#### `man/bob.1` (3 fixes)

**1. Références au flag `--list-checks` supprimées** (ligne 270). Le flag est documenté dans le man mais **n'existe pas** dans `bob/cli.py`. Le vrai format pour lister les sections est `bob --check=list`. Un user tapant `bob --list-checks` obtient `Error: Unknown option: '--list-checks'`.

**2. Claim sur `--min-level=info` valeur valide retirée** (ligne 262). Le man listait trois valeurs valides : `info / warn / alert`. Mais `cli.py:388,396` rejette explicitement `info` (seulement `warn` ou `alert` acceptés ; `info` serait un no-op puisque INFO est le plancher implicite).

**3. Liste des valeurs `--format=FMT` complétée** (ligne 99). Le man listait `text / json / markdown`. Le vrai tuple `_VALID_FORMATS` dans `cli.py:458` est `("json", "json-full", "csv", "markdown", "html")` — manquent `json-full`, `csv`, `html`, et `text` n'est **pas** une valeur valide de `--format=` (c'est le mode de sortie par défaut implicite ; `bob --format=text` est rejeté au parse).

#### `man/bob-profile.5` (3 fixes)

**1. Références au flag `--list-profiles` supprimées** (ligne 53). Même classe de bug que `--list-checks` : le man documentait un flag qui n'existe pas.

**2. "Jusqu'à 5 niveaux d'héritage" → "Jusqu'à 8 niveaux"** (ligne 57). La vraie constante est `_MAX_EXTENDS_DEPTH = 8` dans `bob/profiles.py:56`, levant `RecursionError` quand dépassée.

**3. SHIPPED PROFILES enrichi avec l'entrée alias `workstation`**. La section listait 3 profils (`server`, `desktop`, `container`) mais `bob/data/profiles/` contient 4 fichiers. Le man documente maintenant `workstation` comme alias de rétrocompatibilité. La description de `container` a aussi été réécrite pour matcher le vrai `container.conf::[skip_sections]`.

#### `DOCUMENTS/AUTOMATION.md` + FR (4 × 2 = 8 fixes)

La doc webhook contenait quatre erreurs significatives qui auraient conduit les intégrateurs à écrire des receivers cassés.

**1. Structure du sample JSON fausse**. La doc montrait `alerts` et `warnings` comme tableaux d'objets `{key, message}`. Le vrai payload JSON les expose en **entiers (compteurs)** (`engine.alert_count`, `engine.warn_count`). Un receiver implémentant `for alert in payload["alerts"]:` crasherait avec `TypeError: 'int' object is not iterable`. Pour énumérer les findings, le receiver doit appeler BOB avec `--json-full` qui ajoute un tableau `findings` top-level. Le sample corrigé inclut les vrais champs (`version`, `score_max`, `network_context`, `public_ip`, `deductions`, `domain_scores`).

**2. Casse du champ `risk` fausse**. Sample montrait `"risk": "LOW"` (uppercase). Le vrai JSON sérialise `engine.level.value` qui est en lowercase (`"low"` / `"medium"` / `"high"` / `"critical"` — voir `bob/scoring.py:45-50`).

**3. Claim sur la condition de webhook fausse**. La doc disait "Le webhook est POSTé **uniquement si des alertes ou avertissements sont présents**". Le vrai code (`bob/__main__.py`) n'a aucun seuil de count — le webhook est POSTé à chaque audit dès qu'une URL est configurée et que `--offline` n'est pas activé, y compris pour les audits clean. La doc corrigée précise "filtrer côté récepteur en inspectant `alerts`/`warnings`/`score`".

**4. Timeout webhook faux**. Doc disait "timeout de 5 secondes" ; la vraie constante est `_TIMEOUT_SECONDS = 10` dans `bob/webhook.py:39`. La même dérive était présente dans `DOCUMENTS/SNAPSHOT.md` et avait été corrigée là pendant les passes d'audit SNAPSHOT — mais la copie dans AUTOMATION.md n'avait pas été propagée. Exemple type de pourquoi les faits dupliqués dans la doc dérivent.

#### `SECURITY_FR.md` (1 fix)

Le header `## Threat model` était resté en anglais quand le fichier a été forké en français. Le contenu du body était déjà traduit ; seul le heading avait été oublié. Corrigé en `## Modèle de menace`.

### `DOCUMENTS/SNAPSHOT.md` — nouvelle cartographie interne

Un nouveau document interne de ~640 lignes a été créé dans `DOCUMENTS/` pour fournir une vue d'ensemble single-page du codebase. Le but est double :

1. **Préparation de refactor** : avant une refactorisation non-triviale, le maintainer n'a plus besoin de re-découvrir la structure, le graphe de dépendances et les contracts gelés module par module.

2. **Briefing sub-agent** : quand on délègue une tâche d'audit profond ou de refactor à un sub-agent, passer SNAPSHOT.md comme premier item de contexte réduit drastiquement l'exploration que l'agent doit faire.

**Contenu** : diagramme ASCII d'architecture · arbre annoté · index des modules `bob/` racine (38 modules) et `bob/checks/` (43 checks) avec LoC et rôles · graphe de dépendances (centralité in/out-degree) · hotspots et ratios tests-to-code · 6 patterns/conventions avec exemples · 7 contracts gelés · surface CLI (~40 long + 21 short) · paths fichiers & env vars · mapping tests-to-source · décisions architecturales · matrice CI · "Chiffres clés".

**Validation** : le document a subi **20 passes successives de correction** contre l'état réel du code, produisant 46 corrections au total. Bugs notables rattrapés : `~18 kLoC` headline → `~28 kLoC` (auto-incohérence entre header et footer qui a survécu 19 passes précédentes) ; le diagramme ASCII montrait `runner.py → domain_scores.py` mais `runner.py` n'importe pas `domain_scores` (vérifié par scan AST) ; description `--show-ignored` fausse ; `--ignore=KEY` listé en Filter alors qu'il s'agit d'une opération Setup qui exit immédiatement ; env var `NO_COLOR` listé comme honoré alors qu'aucun chemin de code ne le lit ; type du champ `network_context` change entre `--json` et `--json-full` ; exemple ScoreEngine manquait le paramètre requis `reason` ; paths cron utilisaient `{name}` mais les vrais paths utilisent `{slug}` dérivé via `make_slug()` ; "5s timeout" → 10s (même correction que AUTOMATION.md) ; "5 compound-risk rules" → 6 ; signature de pattern ne matchait pas le style majoritaire ; claim sur le storage des références CIS était trompeur.

Le document est 100% anglais (une passe Franglais a rattrapé 4 expressions françaises résiduelles). Il est interne (pas shipped dans `debian/bob-core.docs` ni `bob.spec %doc`) parce que l'audience est le maintainer et les sub-agents, pas les utilisateurs finaux.

### Harmonisation cosmétique des jauges

Toutes les barres de progression basées sur le score dans l'UI terminale partagent maintenant un schéma de couleur unique via un nouveau helper `bob.output.score_bar(score: int) -> str`. La logique de couleur miroite `display._disk_bar` mais avec des seuils inversés — pour les scores, **haut = bon** :

| Plage de score | Couleur | Sémantique |
|---|---|---|
| ≥ 8 / 10 | vert | sain |
| 5 – 7 / 10 | jaune | modéré |
| 0 – 4 / 10 | rouge | critique |

Avant ce changement, quatre emplacements rendaient les barres en `█ * filled + ░ * empty` brut monochrome — visuellement plat, sans information de gravité conveyée par la couleur. Les barres des partitions disques dans `display.py::_disk_bar` étaient déjà colorées (avec les mêmes seuils appliqués au *pourcentage d'utilisation*, où haut = mauvais — d'où la sémantique inversée). Le nouveau helper aligne le reste de l'UI sur ce style établi.

Renderers affectés (délégation d'une ligne chacun) :

- `bob/watch.py::_score_bar` — l'affichage live du mode `--watch`.
- `bob/breakdown.py::_bar` — le chemin de calcul du score `--breakdown`.
- `bob/domain_scores.py::render_domain_scores` — les barres de sous-scores par domaine dans le résumé d'audit.
- `bob/manage_logs.py` (rendu d'historique à la ligne 69) — la sparkline des scores passés dans le TUI `--manage-logs`.

Le flag `--no-color` / `-n` continue de neutraliser les couleurs.

### Refonte complète de la bash completion (`bob/data/bob.bash-completion`)

#### Bug critique : complétion de valeur `--xxx=<TAB>` échouait silencieusement

L'amélioration la plus visible pour l'utilisateur est la correction d'un échec silencieux long-standing dans la complétion de valeurs. Taper `bob --check=<TAB>` (ou n'importe lequel de `--skip=`, `--min-level=`, `--format=`, `--profile=`, `--lang=`, `--target=`, `--webhook-format=`, `--output=`) ne montrait aucune suggestion.

La cause racine est la façon dont bash split la ligne de commande en mots pour la completion. Avec `COMP_WORDBREAKS` par défaut contenant `=`, taper `bob --check=` et appuyer TAB fait que bash split la ligne en `["bob", "--check", "="]` avec `COMP_CWORD=2` pointant sur le `=` lui-même. La fonction de completion lisait `${COMP_WORDS[COMP_CWORD]}` pour le mot courant — retournant `"="` au lieu de la chaîne vide. Le `compgen -W "${section_list}" -- "="` subséquent ne matchait rien.

Le fix est d'utiliser la convention par arguments positionnels de la lib bash-completion : quand bash invoque une fonction de completion, il passe trois arguments positionnels — `$1` est le nom de la commande, `$2` est le mot courant **propre** stripé de tout préfixe de word-break `=`, et `$3` est le mot précédent. Lire `$2`/`$3` au lieu de `${COMP_WORDS[COMP_CWORD]}`/`${COMP_WORDS[COMP_CWORD-1]}` évite complètement le cas du split `=`.

Le bug a été diagnostiqué en ajoutant un wrapper de debug autour de la fonction dans la session bash interactive de l'utilisateur (Bash 5.2.21), traçant la sortie `set -x` pour chaque pression TAB. Le diagnostic a révélé `words=[bob --check =] cword=2 cur=[=]` après avoir tapé `bob --check=<TAB>` — confirmant l'exposition COMP_WORDS du split brut contre le `$2=""` propre passé via les args positionnels.

Ce bug était présent depuis la release initiale v0.1.0 et a survécu à tous les audits subséquents parce que l'approche de test manuel (mettant `COMP_WORDS=(bob "--check" "=" "")` avec `COMP_CWORD=3`) produisait une forme de word-array différente du vrai bash interactif.

#### Autres corrections

- **Renommage de fonction** : `_ufw_audit` → `_bob`. Le nom de fonction legacy datait d'avant le rename du projet en "Bodyguard Of Bits".
- **Code mort supprimé** : `_ufw_audit_install()` + `complete -F install.sh` enregistraient une completion pour un script `install.sh` qui n'existe plus.
- **Liste des sections factorisée dans `_SECTIONS`**, matchant `bob --check=list` exactement. Suppression de `firewall` (check core, non filtrable). Ajout de `iptables_nft`, `samba`, `desktop_apps` (ajoutés à `_ALL_SECTIONS` entre v0.3.x et v0.4.x mais jamais propagés à la liste de completion).
- **Parité des long-options avec `cli.py`** : ajout de `--check=`, `--skip=`, `--output-dir=`, `--breakdown`, `--no-colour`. Short-options gagne `-B`. Total : 21 short, ~40 long options.
- **Nouveau handler de valeur `--skip=`** (symétrique avec `--check=` minus la valeur spéciale `list`).
- **Tous les handlers de valeur supportent les deux formes** `--xxx=value<TAB>` et `--xxx value<TAB>`.

### CI — release GitHub automatique au push de tag (`.github/workflows/publish.yml`)

Le workflow de publish gagne un 4e job `github-release` qui tourne après le succès du publish PyPI. Le pipeline complet est maintenant :

```
git push --tags
  ↓
test       (matrice Python 3.10/3.11/3.12/3.13)
  ↓
build      (sdist + wheel, uploadés en artifact)
  ↓
publish    (PyPI via Trusted Publishing OIDC)
  ↓
github-release  ← NOUVEAU
  • Extrait le titre depuis la ligne table de CHANGELOG.md
  • Extrait le body depuis la section DOCUMENTS/CHANGELOG_FULL.md
    entre "## [vX.Y.Z]" et le prochain header "## [v" (via awk)
  • Crée la release via softprops/action-gh-release@v2
  • Attache wheel + sdist comme assets de release
  • Marque comme latest
```

Sécurités : `needs: publish` (release uniquement si PyPI réussit), check explicite que la section CHANGELOG_FULL existe (échoue avec `::error::` sinon), permission limitée à `contents: write`.

Avant cette automatisation, les releases GitHub étaient créées manuellement après chaque publish PyPI.

### Tests

Aucun nouveau test ajouté. 3 tests dans `tests/test_breakdown.py::TestBar` adaptés pour stripper les séquences d'échappement ANSI avant d'asserter le contenu visible de la barre (les barres sont maintenant des strings ANSI-colorés au lieu de `█░░░░░░░░░` brut). 4500/4500 tests passent toujours.

---

## [v0.4.6] — 17-05-2026

**La passe terrain v0.4.5 a fait remonter deux bugs reproductibles.** Les deux sont maintenant corrigés. Périmètre strictement limité — hotfix ciblé, aucun changement de comportement en dehors des deux scénarios rapportés.

### Contexte de validation : la passe terrain v0.4.5

Avant d'ouvrir v0.4.6, 13 audits ont été exécutés sur 6 systèmes distincts en utilisant la release v0.4.5 publiée sur PyPI :

| Système | Audits | Verdict |
|---|---|---|
| Mint dev (host) | 1 | propre |
| Debian 13 VM | 3 (pré + `apt upgrade` + `dist-upgrade`) | Bug 2 manifesté après remédiation |
| Kali Rolling VM | 1 | propre |
| Mint test VM | 3 (pré + `apt upgrade` + `dist-upgrade` + `autoremove`) | Bug 1 manifesté après autoremove |
| Ubuntu 26.04 LTS VM | 1 | propre |
| so6desktop production (Linux Mint 22.3) | 2 (pré + post `dist-upgrade` + `autoremove`) | Bug 1 manifesté en production |

Deux bugs reproduits. Le Bug 1 s'est manifesté sur du matériel de production — confirme que ce n'est pas un artefact VM mais le résultat routinier de tout utilisateur nettoyant une image noyau obsolète. Le Bug 2 était lié à une transition spécifique (`WARN/ALERT → OK only` dans un domaine) — périmètre plus étroit qu'initialement supposé, mais une vraie régression d'ergonomie sur le chemin de remédiation.

### Bug 1 — Le listing noyaux ne filtrait pas sur l'état `ii` (installé)

**Déclencheur** : `apt remove linux-image-X` (ou sa forme transitive via `apt dist-upgrade` / `autoremove`) laisse le paquet en état `rc`. `rc` signifie "supprimé, config-files restants" : le binaire noyau dans `/boot` a disparu (`/etc/kernel/postrm.d/initramfs-tools` s'exécute et supprime `initrd.img-X`), mais l'entrée du paquet reste dans la base dpkg avec ses fichiers de config dans `/etc`. Le paquet ne disparaît complètement que si `apt purge` est utilisé ou `dpkg --remove --purge` est exécuté.

**Ce que BOB faisait** : dans `bob/checks/kernel_modules.py`, la construction du snapshot appelait

```python
dpkg_out = _run("dpkg-query", "-f", "${Package}\n", "-W", "linux-image-[0-9]*", timeout=10)
```

Ce format imprime le nom du paquet sans considération d'état. `_parse_installed_kernels` supposait ensuite que chaque ligne retournée était un noyau installé et les listait toutes.

**Ce que l'utilisateur voyait** : la sortie BOB listait des noyaux qu'`apt` avait déjà supprimés. Exemple concret sur so6desktop après `apt dist-upgrade` (qui a supprimé `linux-image-6.17.0-20-generic`) + `apt autoremove` (qui a supprimé `linux-hwe-6.17-headers-6.17.0-20`) :

```
→ Installés  : 6.17.0-19-generic, 6.17.0-20-generic, 6.17.0-22-generic, 6.17.0-23-generic (*)
→ Obsolètes  : 6.17.0-19-generic
→ sudo apt purge linux-image-6.17.0-19-generic
```

`6.17.0-20-generic` avait déjà disparu — son entrée dpkg était `rc`, pas `ii`. Le compteur "Obsolètes" était sous-évalué par effet de bord (1 listé au lieu de 2). La suggestion de purge ciblait le bon noyau, mais le reste du listing était faux.

**Correctif** : dpkg-query est maintenant invoqué avec l'abréviation de statut incluse.

```python
dpkg_out = _run(
    "dpkg-query", "-f", "${db:Status-Abbrev}|${Package}\n",
    "-W", "linux-image-[0-9]*",
    timeout=10,
)
```

`${db:Status-Abbrev}` est une abréviation 2-caractères de `action désirée + état actuel` :

| Code | Désiré | Actuel | Signifie | Action BOB |
|------|--------|--------|----------|------------|
| `ii` | install | installé | paquet installé normal | garde |
| `hi` | hold | installé | installé mais sur apt-mark hold | garde |
| `rc` | remove | config-files | supprimé par `apt remove`, binaires /boot partis | **exclut** |
| `pn` | purge | non-installé | programmé pour purge, jamais réinstallé | exclut |
| `un` | unknown | non-installé | dpkg connaît le nom mais rien d'autre | exclut |
| `iU` | install | unpacked | en cours d'installation, binaires peut-être pas exécutables | exclut |
| `iF` | install | half-configured | transitoire en cours d'installation | exclut |
| `iW` | install | triggers-awaited | transitoire | exclut |

`_parse_installed_kernels` ne garde maintenant que les lignes dont le 2e caractère est `i` — le 2e char encode l'état actuel (n=non-installé, c=config-files, H=half-installed, U=unpacked, F=half-configured, W=triggers-awaited, i=installé). Toute ligne où les binaires sont *garantis* présents passe ; tout ce qui est transitoire ou supprimé est filtré.

**Rétro-compatibilité** : le parser accepte toujours les lignes plain `linux-image-…` sans préfixe `|`. C'est préservé pour deux raisons : (1) les fixtures de tests dans `TestParseInstalledKernels` utilisent le format legacy ; (2) tout chemin de code ou futur appelant qui produit juste le nom du paquet (ex. un fallback si `${db:Status-Abbrev}` est indisponible) continue de fonctionner.

### Bug 2 — Le score baissait après remédiation

**Déclencheur** : un domaine transite de "a au moins un WARN/ALERT" à "émet uniquement des findings OK". Le scénario de référence est `updates` : pré-remédiation un WARN `updates.security_pending` existe, l'utilisateur exécute `apt upgrade`, le run BOB suivant ne voit plus que `updates.ok`.

**Ce que BOB faisait** : `bob/domain_scores.py::active_domains_from_engine()` collectait les domaines pour inclusion dans la moyenne de score globale. Il appliquait un filtre `_actionable = (FindingLevel.WARN, FindingLevel.ALERT)` — un domaine entrait dans le set actif uniquement s'il avait au moins un finding WARN ou ALERT (ou une déduction avec une clé, ce qui est impliqué par WARN/ALERT en pratique).

**Ce que l'utilisateur voyait** : sur Debian 13 VM avec une mise à jour de sécurité en attente :

- **Audit avant `apt upgrade`** — WARN `updates.security_pending` actif → domaine `updates` dans le set actif à 8/10. Autres domaines actifs : `ssh`, `hardening`, etc. Global = moyenne ≈ 7/10.
- **`apt upgrade`** résout la mise à jour de sécurité.
- **Audit après `apt upgrade`** — le check `updates` émet maintenant `updates.ok` et rien d'autre. Le filtre rejette `updates` du set actif. `ssh`, `hardening`, etc. encore présents. La moyenne globale est maintenant sur `N-1` domaines. Maths : retirer un domaine qui avait 8/10 d'une moyenne où plusieurs domaines restants sont en-dessous de 8/10 → moyenne *augmente*. Mais retirer un domaine qui avait 8/10 quand plusieurs domaines restants sont à 4–6/10 fait baisser la nouvelle moyenne. Sur Debian 13 la nouvelle moyenne a baissé de 7 à 6.

L'effet observable utilisateur : faire la bonne chose (appliquer les patches de sécurité) faisait baisser le score. Anti-incitatif sur un outil de hardening.

**Pourquoi le filtre existait** : probablement pour cacher les domaines où aucun service n'est installé (ex. Samba non installé → pas de findings `samba.*` → domaine absent de l'affichage). Cet objectif est légitime. L'implémentation confondait "pas de finding actionnable" avec "pas de signal du tout" et produisait le mauvais comportement à la transition WARN→OK.

**Correctif** : le filtre est maintenant `_actionable = (FindingLevel.OK, FindingLevel.WARN, FindingLevel.ALERT)`. Un domaine est considéré actif quand *n'importe quel* check de ce domaine émet un signal de santé reconnaissable. Les domaines INFO-only restent cachés — la terrain Mint test (seul `updates.regular_pending` INFO présent, pas de WARN, pas de OK) a confirmé que le bug ne s'y manifeste pas, donc la ligne conservatrice est d'exclure INFO de la promotion.

La sémantique correspond maintenant à ce que le docstring affirmait déjà ("Used to hide domains whose service is not installed") — service non installé signifie pas de findings émis, ce qui garde le domaine absent.

**Comportement de score avec le correctif** :

```
Avant remédiation : avg(updates=8, hardening=4, …) / N          = 7
Après remédiation : avg(updates=10, hardening=4, …) / N         = ~7+    ← CORRECT
```

Les domaines avec uniquement des findings OK contribuent maintenant leur score 10/10 propre à la moyenne globale, ce qui est mathématiquement le bon résultat : un domaine qui audite propre devrait tirer la moyenne vers le haut, pas être silencieusement retiré.

**Effets en cascade** à connaître :

- Les domaines où le check pertinent émet toujours un OK (parce que le service est universellement présent et clean sur le système) seront désormais toujours dans le set actif. Sur Ubuntu 26.04 LTS, où beaucoup de checks émettent du pur OK, le dénominateur de la moyenne globale grossit. C'est intentionnel — ces domaines étaient toujours "audités" mais invisibles au score.
- Affichage des scores par domaine : `render_domain_scores` filtre par `active_domains`, donc des domaines 10/10 précédemment cachés peuvent maintenant apparaître. Le breakdown devient plus honnête sur quels domaines ont contribué.

### Tests

**`tests/test_kernel_modules.py`** — nouveaux tests dans `TestParseInstalledKernels` :

- `test_status_prefixed_ii_kept` — les lignes `ii ` basiques produisent la liste de versions.
- `test_status_prefixed_rc_excluded` — reproduction directe du Bug 1 : une ligne `rc ` pour `6.8.0-52` est exclue tandis qu'une ligne sœur `ii ` pour `6.8.0-55` est gardée.
- `test_status_prefixed_excludes_all_non_installed_states` — `ii`, `rc`, `pn`, `un`, `iU` cohabitent ; seul `ii` survit.
- `test_status_prefixed_hi_kept` — les paquets en hold restent dans la liste (les binaires sont encore sur disque).
- `test_mixed_legacy_and_status_prefixed_format` — rétro-compatibilité : une sortie dpkg unique mélangeant lignes préfixées et non-préfixées parse correctement.

**`tests/test_domain_scores.py`** — nouvelle classe `TestActiveDomainsIncludesOK` :

- `test_ok_finding_makes_domain_active` — assertion directe du nouveau comportement de filtre.
- `test_warn_finding_makes_domain_active` — ancien comportement préservé.
- `test_alert_finding_makes_domain_active` — ancien comportement préservé.
- `test_info_only_finding_does_not_promote_domain` — garde-fou de l'exclusion INFO ; si ce test échoue, les domaines INFO-only ont commencé à fuiter dans le set actif.
- `test_no_findings_no_active_domains` — moteur vide retourne toujours un set actif vide ; baseline regression guard.
- `test_remediation_keeps_domain_at_max_score` — reproduction directe Debian 13 sous forme de test : ssh a un WARN (8/10), updates remédié à OK seulement. Asserte que `compute_global_from_domains` retourne `(8+10)/2 = 9` au lieu de `8`.

### Compte de tests

4500 passés (+11 vs v0.4.5). Aucune régression sur le reste de la suite.

### Ce qui NE change PAS

- Le JSON schema reste version 1. Aucun nouveau champ, aucun champ supprimé, aucun champ renommé.
- `EXPLAIN_KEYS` inchangé.
- Aucune nouvelle clé de locale ; aucune clé supprimée.
- API Python publique de `bob.domain_scores` inchangée (signature de `active_domains_from_engine`, type de retour, aucun nouvel argument).
- API Python publique de `bob.checks.kernel_modules` inchangée (signature de `_parse_installed_kernels`, type de retour — elle a toujours pris une string et retourné `List[str]`, et le sens de la string est upward-compatible).
- Aucune nouvelle dépendance (toujours 0 dépendance runtime hors stdlib).

### Hors périmètre (différé)

- **Audit hardening complet par sub-agent** : demandé en parallèle de v0.4.6, différé car la tentative précédente a hit le cap mensuel d'usage de l'org avant de produire un rapport. Voir `[[audit-hardening-en-attente-v0-4-5]]` dans la mémoire agent — à relancer en prochaine session une fois le quota reset.

---

## [v0.4.5] — 16-05-2026

**Release de hardening de l'infrastructure de tests.** v0.4.4 a ajouté `tests/test_locale_coverage.py` pour attraper la classe de régression `logs.attempts` — clés retirées des fichiers de locale alors qu'elles sont encore référencées dans le code. L'implémentation fonctionnait et avait déjà été étendue en v0.4.4 avec trois fixes issus d'une review ChatGPT (negative lookbehind resserré, couverture exhaustive `explain.*`, parité des placeholders). Mais la machinerie sous-jacente reposait encore sur un scan regex des fichiers source, avec des limites documentées : faux positifs dans docstrings, fragilité des call sites multilignes, edge cases d'appels d'attributs. v0.4.5 remplace le pipeline regex par un vrai parsing AST.

### Pourquoi ça compte

Le test attrape une vraie classe récurrente de bug — fallbacks silencieux de locale qui n'apparaissent qu'au test terrain (la sentinelle v0.4.3 `[logs.attempts]` a été découverte post-tag, pas par la CI). Tout l'intérêt d'automatiser ça est pour que la CI attrape la régression avant le tag. Si l'automation elle-même a des angles morts cachés, le filet de sécurité fuit.

Trois problèmes structurels avec le scan regex du code source Python :

1. **Les matches dans docstrings sont des faux positifs qui ressemblent à des vrais.** `bob/i18n.py` documente l'API `t()` avec des exemples comme `t("samba.open_world")` et `t("log.blocked_attempts", count=42)`. Le regex matchait ces exemples comme s'ils étaient de vrais sites d'appel, forçant v0.4.4 à maintenir une allowlist `_KEY_EXCLUSIONS` avec deux entrées. Chaque futur exemple de doc d'API aurait fait grossir cette liste — c'est l'anti-pattern classique "l'allowlist mange les bugs".
2. **Les call sites multilignes sont dépendants du formatage.** Un appel écrit `_t(\n    "foo.bar",\n    x=1,\n)` est sémantiquement identique à `_t("foo.bar", x=1)` mais le regex nécessite que la parenthèse ouvrante et le guillemet ouvrant soient proches. Le regex v0.4.4 gérait la plupart des layouts mais le contrat était implicite et fragile.
3. **Les appels d'attribut passent à travers certains lookbehinds.** v0.4.4 a resserré le negative lookbehind de `[A-Za-z0-9_]` à `[A-Za-z0-9_.]` pour rejeter `obj._t(...)`. Ça couvrait le cas commun, mais la règle était rétroactive — chaque nouvel edge case (identifiants unicode, backslashes de continuation) demanderait un autre tweak du lookbehind.

### Comment l'AST règle les trois

```python
def _is_translation_call(node: ast.Call) -> bool:
    return (
        isinstance(node.func, ast.Name)
        and node.func.id in _TRANSLATION_FUNC_NAMES
    )
```

`ast.parse(source)` retourne l'arbre syntaxique Python. Trois propriétés structurelles résolvent les trois problèmes :

- **Les docstrings sont inertes.** Elles apparaissent comme `ast.Constant(str)` directement dans un body de fonction/classe/module — pas dans un `ast.Call`. Le walker ne les voit jamais.
- **Le whitespace est transparent.** Le même node `ast.Call` représente chaque variante de formatage. Multilignes, single-line, virgule trainante — tous identiques.
- **L'accès attribut est un type de node différent.** `obj._t(...)` produit `ast.Call(func=ast.Attribute(...))`. Le check `isinstance(node.func, ast.Name)` l'élimine par construction. Pas de tweaks de lookbehind, pas de maintenance de liste négative.

L'allowlist `_KEY_EXCLUSIONS` est complètement supprimée. Il n'y a pas de chemin futur où elle grossit.

### Ce qui est préservé

Le contrat externe des tests est identique. Les mêmes 9 tests dans trois classes :

- `TestLocaleCoverage` (5 tests) : scan corpus, résolution EN, résolution FR, parité EN/FR, baseline sanity.
- `TestExplainNamespaceCoverage` (3 tests) : couverture exhaustive `explain.<clé>.{title,why,how}` générée depuis `EXPLAIN_KEYS` figée.
- `TestPlaceholderParity` (1 test) : les placeholders `{nom}` matchent entre en.json et fr.json.

Mêmes fixtures (`en_data`, `fr_data`, `static_keys`, `explain_leaves`), mêmes assertions. Seuls `_all_t_keys()` et deux petites fonctions helper (`_is_translation_call`, `_literal_key_arg`) ont changé.

### Performance

Le parsing AST est plus lent que le regex : 0,32 s vs 0,06 s pour ce fichier de test (~5× plus lent). En absolu négligeable — la suite de tests complète termine toujours en 6,5 s. Aucune optimisation nécessaire.

### Ce que cette release ne change pas

Cette release modifie **uniquement** `tests/test_locale_coverage.py`. Aucun fichier source dans `bob/` n'est touché. Aucun comportement runtime n'est altéré. Le compteur de tests reste à 4489. La forme regex v0.4.4 et la forme AST v0.4.5 retournent le même ensemble de clés sur le codebase actuel — vérifié en lançant les deux contre `bob/`. Le refactor est préventif, pas correctif.

### Tests

4489/4489 — inchangé vs v0.4.4. Les 9 tests dans `tests/test_locale_coverage.py` passent tous sur la nouvelle implémentation AST sans aucune modification de leurs assertions.

### Reporté à une release ultérieure

Cette release ne change pas les items existants de la roadmap :

- Phase 2 Option A — migration systématique `Finding.template_vars` sur les ~37 checks non-pilotes. Toujours en piste pour v0.5.0+. `tests/test_template_vars_migration.py` continue à exposer la dette.
- Matrice CI multi-distros (Debian/Ubuntu/Mint/Kali en conteneurs) et PKGBUILD AUR — contribution communautaire bienvenue.
- Cleanup cosmétique M3 (`os.path` → `pathlib` dans 4 fichiers).

---

## [v0.4.4] — 15-05-2026

**Release de hardening terrain cross-distro.** Quatre nouveaux tests sur VM (Debian 13, Kali Rolling, Linux Mint 22.3, Ubuntu 26.04 LTS — toutes installées depuis PyPI via `pipx upgrade bodyguard-of-bits`) ont fait remonter un bug critique, trois régressions cosmétiques mineures, et confirmé en production que les fixes v0.4.3 fonctionnent. Tous les résultats plus les items reportés de la passe d'audit v0.4.3 (S4 redesign symlink, M4 refactor ports, I2 vague 2 `key=`, test couverture locale) sont groupés dans cette release.

### Le bug critique — et pourquoi il compte

`bob/checks/updates.py` rapportait "système à jour" sur **chaque installation fraîche Debian-family qu'on a testée**. Sur Ubuntu 26.04 LTS spécifiquement, cela signifiait **21 mises à jour officielles de sécurité LTS passées en silence**. Pour un outil d'audit hardening, c'est la pire classe de bug — un faux-négatif sur un check critique de sécurité qui ruine la confiance dans la totalité de la sortie.

Deux causes combinées :

1. **La commande `apt-get -s upgrade` sur laquelle BOB s'appuyait est conservatrice.** Elle refuse d'upgrader tout paquet qui exigerait d'installer un nouveau paquet ou d'en retirer un autre. Sur Debian/Ubuntu, chaque transition de noyau (`linux-image-amd64 → linux-image-6.12.86-amd64`) et chaque bump de soname déclenche exactement ce cas — toute la fermeture transitive est mise de côté. Les utilisateurs réels lancent routinièrement `apt full-upgrade` / `apt dist-upgrade` précisément pour cette raison. BOB simulait un workflow que personne n'utilise réellement.

2. **Le cache APT vit dans `/var/cache/apt/pkgcache.bin` et ne se rafraîchit que quand `apt update` tourne.** Sur les installations vierges (typique des VMs de test, mais aussi de tout utilisateur qui dépend des rafraîchissements `unattended-upgrades` qui peuvent avoir échoué), le cache a des jours ou des semaines. BOB lisait cet état périmé et rapportait "0 en attente" sans aucune réserve.

Le fix superpose trois changements dans `bob/checks/updates.py` :

- **`apt-get -s upgrade` → `apt-get -s dist-upgrade`** dans `_collect_pending_updates()`. Aligne la simulation avec ce que les utilisateurs lancent réellement. La détection des mises à jour de sécurité (via le suffixe `-security` sur la suite source) est inchangée — `dist-upgrade` produit les mêmes lignes `Inst`, simplement plus.
- **Check de fraîcheur du cache.** Nouveau champ `apt_cache_age_days: int | None` sur `UpdatesSnapshot`, peuplé en stat-ant le mtime de `/var/cache/apt/pkgcache.bin`. Quand le cache a plus de 7 jours, le check émet un nouveau WARN `updates.apt_cache_stale` avec une recommandation `sudo apt update`. Le seuil mirrore les fenêtres typiques de rafraîchissement `unattended-upgrades`.
- **Cross-check vs `apt list --upgradable`.** Nouveau champ `upgradable_count: int | None`, peuplé en parsant la sortie d'`apt list --upgradable` (comptage des lignes `pkg/suite ... [upgradable from: ...]`). Quand la simulation `dist-upgrade` rapporte 0 en attente mais `apt list` rapporte N > 0, le snapshot est incohérent — probablement un état transitoire (paquets bloqués, dépendances cassées) — et un nouveau WARN `updates.dist_upgrade_inconsistent` se déclenche avec `sudo apt update && sudo apt list --upgradable` pour investigation.

La cascade compte autant que le fix racine. La synthèse "Surface d'attaque" en fin de chaque audit avait une ligne `Mises à jour sécurité` qui lisait directement depuis les findings du moteur — si aucune clé `updates.security_pending` n'était émise, elle affichait `✔ à jour`. Évidemment "aucune clé émise" était exactement le bug. `bob/exposure.py` vérifie maintenant les deux nouvelles clés WARN et affiche `⚠ état inconnu — cache APT obsolète ou incohérent` au lieu du faux `✔`. Refuser de revendiquer "OK" quand la source de données n'est pas fiable est le bon contrat pour un outil de sécurité.

### Trois régressions cosmétiques depuis les VMs cross-distro

Elles ne changent pas le scoring mais elles changent la confiance. Un outil de hardening avec une sortie confuse ou contradictoire entraîne les utilisateurs à l'ignorer.

**Cas AppArmor "0 profil chargé"** (attrapé sur Kali, où l'install par défaut a le module noyau activé mais livre zéro paquet de profils). v0.4.3 émettait `AppArmor actif mais aucun profil en mode enforce (0 en plainte)`. La parenthèse se contredisait — impliquant que des profils en mode plainte existent alors qu'il n'y en a littéralement aucun. Le fix dans `bob/checks/mac_policy.py` distingue trois états explicitement :
- `enforce > 0` : chemin OK, langage actuel préservé.
- `enforce == 0 ET complain > 0` : chemin existant `apparmor_no_enforce` avec le conseil "passez en enforce" (ce cas s'applique à une vraie mauvaise config).
- `enforce == 0 ET complain == 0` (nouveau) : clé dédiée `apparmor_no_profiles` avec le message "AppArmor actif mais aucun profil chargé — le framework tourne sans rien à appliquer" et une recommandation d'installer `apparmor-profiles` / `apparmor-profiles-extra`. Le profil server applique une déduction de −1 ; le profil desktop garde ça en INFO.

**SMART "tous passés" sur systèmes uniquement virtuels** (attrapé sur Kali, /dev/vda). La sortie était :
```
ℹ /dev/vda — SMART non applicable (équipement virtualisé ou non supporté)
✔ Tous les disques ont passé le contrôle SMART — aucun attribut critique détecté
```
Logiquement incohérent — si aucune lecture SMART n'a tourné, rien n'a passé. `bob/checks/disk.py` n'émet maintenant le succès `disk.ok` "tous passés" que si au moins un check SMART **réel** (non-virtuel) a effectivement retourné un résultat. Sur les VMs et conteneurs où tous les disques sont virtuels, la ligne est simplement absente.

**Liste des ports ouverts DDNS rendue comme sous-items orphelins** (attrapé sur Mint test VM avec ddclient + masbateno.duckdns.org). Précédemment :
```
⚠ DDNS actif avec port(s) ouverts sans restriction — vérifiez que l'exposition est intentionnelle
ℹ Si cette exposition est intentionnelle : maintenez les services à jour...
    → 22/tcp
    → 80/tcp
```
Les lignes `→ 22/tcp` attachaient visuellement au conseil INFO mais appartenaient logiquement au WARN — un lecteur ne peut pas savoir quoi faire avec "22/tcp". Le fix dans `bob/checks/ddns.py` interpole la liste dans le message WARN lui-même : `DDNS actif avec port(s) ouverts sans restriction (22/tcp, 80/tcp) — vérifiez que l'exposition est intentionnelle`. La boucle de print orpheline dans `bob/runner.py` est retirée. Le champ `result.open_ports` est préservé pour les consommateurs programmatiques (diff baseline compare.py, sortie JSON, tests).

### Items reportés de l'audit v0.4.3, tous appliqués

**S4 redesign — lectures ssh symlink-safe.** v0.4.3 avait explicitement reporté ceci parce que le fix le plus simple (`_is_safe_config_path()` rejette tous les symlinks) aurait cassé les setups dotfiles légitimes où les utilisateurs symlinkent `~/.ssh/config` depuis un repo git-managé. Le bon design accepte les symlinks qui résolvent dans le home de l'owner mais rejette ceux pointant ailleurs (un attaquant avec write access sur le home d'un utilisateur plaçant un symlink vers `/etc/shadow` ferait fuiter le contenu de fichiers système dans le rapport d'audit). Nouveau helper `_is_safe_user_path(path, owner_home)` dans `bob/checks/_run.py` :

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

Appliqué dans `bob/checks/ssh.py` sur `authorized_keys`, `~/.ssh/config`, et `known_hosts`. L'existant `_is_safe_config_path` (rejette tout symlink, pas d'exemption home-bounded) est conservé pour les chemins système comme `/etc/cron.d/`, `/etc/sudoers.d/`, et `/var/spool/cron/crontabs/` où tout symlink est suspect.

**M4 refactor — `_parse_ufw_covered_ports`.** Le fix v0.4.3 pour le faux positif `_is_covered_by_ufw` (où un numéro de port trouvé dans une IP source comme `192.168.1.22` "couvrait" faussement le port 22) était correct mais architecturalement fragile — il compilait un nouveau regex pour chaque port vérifié contre le même texte de règles UFW, et tout tweak futur risque de réintroduire le faux positif. Le refactor dans `bob/checks/ports.py` parse la chaîne de règles **une seule fois** au début de `check_ports()` dans un `set[tuple[int, str | None]]` de tuples (port, proto) couverts, puis les lookups deviennent des appartenance O(1). Le `_UFW_RULE_RE` au niveau module est ancré sur le début de la colonne "To" — la classe de faux positif est maintenant impossible par construction. Les deux formes (snapshot et string) d'`_is_covered_by_ufw` sont acceptées pour rétrocompatibilité avec tout caller externe.

**I2 vague 2 — `key=` sur les findings restants.** v0.4.3 couvrait les 4 fichiers les plus touchés (`docker.py`, `firewall_stack.py`, `network_context.py`, `ports.py`). Relancer l'audit sur les checks restants a révélé que `disk.py`, `docker_audit.py`, `desktop_apps.py`, `memory.py`, `suid_audit.py` étaient déjà à 100% de couverture key. Seuls `services.py` (10 sites) et `virtualization.py` (2 sites) avaient besoin de travail — les deux complétés ici. Le codebase a maintenant chaque appel `result.alert/warn/info/ok/add_deduction` câblé avec un `key=` stable pour `--ignore`, les profils d'audit, les consommateurs JSON, et les lookups `--explain`.

**Test de couverture i18n.** v0.4.3 avait eu une quasi-régression — quand le refactor M6 a retiré `logs.attempts` des deux fichiers de locale, 7 sites d'appel dans `bob/display.py` la référençaient encore. Les appels `_t("logs.attempts")` retournaient la clé brute en fallback, produisant la sentinelle `[logs.attempts]` que seul le test terrain a attrapée (post-push v0.4.3). Nouveau `tests/test_locale_coverage.py` tourne à chaque commit :

- Scanne tout `bob/**/*.py` pour les appels `t("KEY")` et `_t("KEY")` via regex, collecte les clés littérales.
- Asserte que chaque clé résout dans **les deux** `en.json` et `fr.json`.
- Asserte la parité structurelle EN/FR (même ensemble de clés feuilles).
- Asserte que les sections à prefixes dynamiques connues (`explain.*`, `services.exposure.*`, `services.state.*`) ont leurs dicts parents dans les deux locales.
- Inclut une baseline sanity (taille corpus de clés ≥ 200) pour qu'un regex cassé ne fasse pas silencieusement passer tous les autres tests trivialement.

Deux faux positifs dans des exemples de docstring (`bob/i18n.py` documente `t("samba.open_world")` et `t("log.blocked_attempts", count=42)` comme exemples illustratifs) sont listés dans `_KEY_EXCLUSIONS`. Tout futur faux positif peut être ajouté de la même façon.

### Écarté du rapport d'audit v0.4.3

- **M3** — `os.path` → `pathlib` dans 4 fichiers (`manage_logs.py`, `suid_audit.py:142,176,180,188`, `secure_boot.py:92`, `ssh.py:1000`). Cosmétique pur. Sera intégré dans une éventuelle release "consistency pass" (imports, type hints, etc.).
- **M7** — Résolution lazy de `_PLUGIN_DIR`. Re-confirmé rejeté de manière permanente. Le "gotcha" (SUDO_USER change mid-process) ne se produit pas dans le modèle d'exécution one-shot de BOB, et la tentative de fix en v0.4.3 cassait 20 tests qui font `patch("bob.registry._PLUGIN_DIR", ...)`.

### Tests

4489/4489 — +21 vs v0.4.3 :
- `tests/test_updates.py` (+10) : deux nouvelles classes de tests couvrant les nouveaux champs `UpdatesSnapshot`. `TestAptCacheStale` (5 tests) exerce le WARN cache-stale sous conditions fresh/stale/missing/boundary. `TestDistUpgradeInconsistency` (5 tests) exerce le WARN cross-check — le scénario précis du bug v0.4.3 est maintenant un test de régression (dist-upgrade retourne 0, apt list rapporte N → WARN).
- `tests/test_mac_policy.py` (+2) : `TestAppArmorNoEnforce::test_no_profiles_desktop_is_info` et `::test_no_profiles_server_deducts_one`, exerçant la nouvelle clé `apparmor_no_profiles` sur les deux chemins profile. L'existant `test_active_with_zero_profiles_at_all` a été réécrit pour asserter la nouvelle clé (il attendait précédemment l'ancienne sortie confuse `apparmor_no_enforce`).
- `tests/test_locale_coverage.py` (+9) : scan corpus complet, résolution locale EN, résolution locale FR, parité EN/FR, couverture des prefixes dynamiques. Le corpus contient 200+ clés statiques (la baseline sanity confirme que notre regex trouve assez de sites d'appel pour être significatif). Plus, en réponse à une review ChatGPT du fichier : negative lookbehind du regex resserré pour aussi rejeter `obj._t(...)` (qui précédemment matchait comme faux positif) ; ajout de `TestExplainNamespaceCoverage` (3 tests) qui génère les chemins attendus depuis la liste figée `EXPLAIN_KEYS` et asserte que chaque `explain.<clé>.{title,why,how}` existe dans les deux locales **en tant que string non-vide** (ceci ferme une zone aveugle — le prefix dynamique `("explain.", "explain")` précédent était un bypass qui masquait silencieusement toute feuille manquante) ; ajout de `TestPlaceholderParity` (1 test) qui asserte que l'ensemble des placeholders `{nom}` est identique entre en.json et fr.json pour chaque clé string commune (protège contre la classe de KeyError runtime `{count}` vs `{cnt}`).

### Validation production

Les fixes v0.4.3 confirmés fonctionnels sur **5 systèmes live différents** :
- **Linux Mint 22.3 dev box** : audit feature complet avec UFW actif, scénario DDNS, Docker installé, Samba, tous les checks rendus proprement sans sentinelles.
- **Linux Mint 22.3 test VM** : même moteur, état hôte différent — confirmé que la régression sentinelle `logs.attempts` avait été corrigée par le patch final v0.4.3.
- **Debian 13** : install minimal, smoke test du chemin cross-distro à travers `mac_policy`, chemin de logs UFW journald-only.
- **Kali Rolling** : 15 binaires SUID inattendus (kismet_cap_*) correctement flaggés comme outillage Kali-spécifique qui nécessite légitimement SUID ; NOPASSWD:ALL dans sudoers détecté avec la bonne sévérité ; AppArmor "0 profils chargés" a fait surface le bug de message confus corrigé ici ; corrélation COMPOUND risk (sudo NOPASSWD + SUID inattendus) a déclenché.
- **Ubuntu 26.04 LTS** : UFW inactif → ALERTE `firewall.inactive` déclenchée avec le `key=` ajouté en v0.4.2, l'entrée EXPLAIN_KEYS ajoutée en v0.4.3, la référence CIS, et le lien `bob --explain firewall.inactive`. La chaîne complète (key → ignore-able + profile-overridable + JSON-matchable + explain-resolvable) est maintenant validée en production sur une famille de distro toute neuve.

### Reporté à une release ultérieure

- Phase 2 Option A — migration systématique `Finding.template_vars` sur les ~37 checks non-pilotes. Toujours en piste pour v0.5.0+. `tests/test_template_vars_migration.py` continue à rendre la dette visible.
- Matrice CI multi-distros (Debian/Ubuntu/Mint/Kali en conteneurs) et PKGBUILD AUR — contribution communautaire bienvenue, non bloquant.
- Cleanup cosmétique M3 (os.path → pathlib).

---

## [v0.4.3] — 15-05-2026

**Release de rattrapage doc qui s'est étendue en passe de hardening.** Cette release a commencé comme la clôture de deux dettes explicitement reportées par v0.4.2 (4 entrées `EXPLAIN_KEYS`, synchro CHANGELOG court). Chemin faisant, un nouvel audit agent sur la totalité du codebase v0.4.2 a fait remonter **1 critique + 5 importants + 8 mineurs + 6 suggestions**. Tous corrigés dans la même release.

Le rapport d'audit complet est documenté inline ci-dessous, organisé par criticité. Faits marquants :

- **C1 (critique)** — `bob --json --json-full` crashait sur chaque système avec `AttributeError`. `bob/json_output.py` lisait 5 attributs (`fail2ban_active`, `auto_updates_enabled`, `apparmor_mode`, `apparmor_enforced`, `apparmor_complain`) depuis `HardeningSnapshot` après leur migration vers `mac_policy.py`. Les lectures mortes ont été supprimées ; la sortie JSON expose désormais uniquement les vrais champs. Un test de régression a été ajouté à `tests/test_json_schema.py::TestFullModeWithOptionalSnapshots` couvrant le chemin `full=True` + `hardening_snapshot` — exactement la lacune qui avait laissé le bug passer en v0.4.2.

- **I1 (important — échec silencieux)** — `datetime.strptime("%b ...")` parse les abréviations de mois anglais en utilisant le `LC_TIME` du **process Python**. Le `LC_ALL=C` des subprocess n'affecte que la sortie de la *commande*, pas Python. Sous `LC_TIME=fr_FR.UTF-8` (courant sur les installations françaises), `strptime("May 14 ...")` levait `ValueError` silencieusement, causant `_read_cert_expiry` à retourner "could not parse notAfter" pour chaque certificat TLS et `_parse_timestamp` à ignorer silencieusement chaque ligne UFW au format syslog. Le score d'audit était systématiquement gonflé sur les systèmes français parce que les certificats expirants et les tentatives de bruteforce étaient invisibles. Nouveau helper `_parse_english_month_day()` dans `bob/checks/_run.py` parse par lookup dict, totalement indépendant de la locale.

- **I2 (important — contrat incomplet)** — Environ 30 appels `result.alert()/.warn()/.info()/.ok()/.add_deduction()` dans `docker.py`, `firewall_stack.py`, `network_context.py` et `ports.py` n'avaient pas l'argument `key=`. Même classe de bug que le C1 v0.4.2, généralisée aux 4 fichiers les plus touchés. Sans `key=`, les findings ne peuvent être matchés ni par `--ignore`, ni par les profils d'audit, ni par les consommateurs JSON externes. Les ~6 fichiers restants ont une densité plus faible de keys manquants et sont tracés pour une passe future.

- **I3 (important — rendu email cassé)** — `bob/report_markdown.py::_inline_format` construisait d'abord le HTML `<a href="...">label</a>` puis appelait `html.escape()` sur le résultat. Tous les liens dans les rapports email rendaient `&lt;a href=&quot;...&quot;&gt;label&lt;/a&gt;` en texte littéral. Ordre d'opérations inversé : escape du texte brut d'abord, puis traduction markdown vers HTML.

- **I4 (important — sous-comptage du score)** — Le regex `_is_covered_by_ufw` n'était pas ancré : il matchait le numéro de port n'importe où sur une ligne de règle UFW, y compris dans les champs IP source. Une IP source comme `192.168.1.22` "couvrait" faussement le port 22. Conséquence : les ports publics réellement non couverts étaient silencieusement classés comme couverts, donc l'audit rapportait un score plus haut que ce que le système méritait. Regex maintenant ancré sur la colonne "To" (juste après `[ N]`).

- **I5 (important — perte silencieuse de données cron)** — `_validate_custom_cron` ne contrôlait que les champs entiers pleins. Des valeurs comme `0-1000 0 * * *` ou `*/200 * * * *` passaient le validateur BOB et étaient ensuite rejetées par cron au parse time, perdant silencieusement la planification. Validateur complet ajouté : ranges, listes, valeurs de step, les 5 champs, avec les bornes correctes (minute 0-59, heure 0-23, jour-du-mois 1-31, mois 1-12, jour-de-la-semaine 0-7).

En plus, les **8 mineurs** (clés locale mortes, cohérence `_C_LOCALE_ENV`, anti-pattern concat i18n, regex redondant, support unités template systemd) et **5 sur 6 suggestions** (env sysinfo, protection symlink sur fichiers cron, logging fallback domain_scores, `__all__`) ont été appliqués. Les 4 points écartés (M3 cosmétique, M4 négligeable, M7 cassait 20 tests au revert, S4 discussion design nécessaire) sont documentés ci-dessous pour traçabilité.

Puis le rattrapage doc initialement prévu :

1. **Les 4 clés firewall promues dans `EXPLAIN_KEYS`.** En v0.4.2 le fix C1 de l'audit agent avait câblé quatre clés (`prerequisites.ufw_missing`, `firewall.inactive`, `firewall.policy_open`, `firewall.policy_unknown`) comme `Finding.key` pour que `--ignore`, les profils d'audit et les consommateurs JSON puissent les matcher. Mais `bob --explain firewall.policy_open` répondait encore "not found" parce que les clés n'étaient pas dans `EXPLAIN_KEYS` et n'avaient pas de contenu title / why / how / CIS associé. Ce contenu avait été reporté parce que rédiger quatre explications complètes en anglais et français est un vrai travail documentaire, pas un fix rapide. Cette release fait ce travail.

2. **CHANGELOG.md (court) corrigé pour v0.4.2.** La section détaillée v0.4.2 ouvrait par "**Aucun changement de code** · 4449/4449 tests (inchangé)" ce qui était factuellement faux : la passe de hardening livrée avec v0.4.2 a modifié 11 fichiers Python et ajouté 3 tests. `CHANGELOG_FULL.md` était déjà correct ; la version courte ne l'était pas. La section a été réécrite avec le détail complet de la passe de hardening (C1, C2, I1-I5, M1-M5, S1-S3). La release v0.4.2 sur PyPI et GitHub est inchangée — c'est un correctif documentaire rétroactif dans `main`.

### Pourquoi une release séparée

La tentation était d'amender v0.4.2 et de force-pusher. Deux raisons de ne pas le faire :

- Le tag v0.4.2 et l'artefact PyPI sont immuables. Une "v0.4.2 avec docs corrigées" sur PyPI est impossible. Une release séparée trace la correction documentaire visiblement.
- Un utilisateur qui lance `bob --version` sur v0.4.2 puis `bob --explain firewall.policy_open` verrait toujours "not found". Avec v0.4.3 il voit du vrai contenu. Le bump de version est la vérité.

### Changements

- **`bob/explain.py`** — le libellé du groupe change de "Firewall Logging" (qui ne contenait que `firewall.logging_off`) à "Firewall", et les quatre nouvelles clés le rejoignent. Le commentaire TODO qui marquait le report en v0.4.2 a disparu. La longueur de `EXPLAIN_KEYS` passe de 112 à 116.
- **`bob/locales/en.json`** — nouvelle entrée `explain.prerequisites.ufw_missing.{title,why,how}`, et trois nouvelles entrées sous `explain.firewall.{inactive,policy_open,policy_unknown}.{title,why,how}`. Chaque entrée suit la même forme que l'`explain.firewall.logging_off` pré-existante : un titre court, un paragraphe expliquant pourquoi c'est un risque de sécurité (pas seulement "ce que" le finding signifie), et une procédure de remédiation numérotée.
- **`bob/locales/fr.json`** — les quatre mêmes entrées en français, traduction idiomatique (pas littérale).
- **`bob/data/cis_refs.json`** — 4 nouvelles entrées. `prerequisites.ufw_missing` → CIS Ubuntu 22.04 L1 3.5.1.1 "Ensure ufw is installed". `firewall.inactive` → CIS 3.5.1.3 "Ensure ufw service is enabled". `firewall.policy_open` et `firewall.policy_unknown` → CIS 3.5.1.7 "Ensure ufw default deny firewall policy" (les deux clés mappent au même contrôle parce que le cas "unknown" est un échec de parsing de la même sortie de statut que `policy_open` détecte positivement).
- **`tests/test_explain.py`** — l'assertion en dur `assert len(EXPLAIN_KEYS) == 112` passe à `116`. Cette assertion est le freeze explicite : quand EXPLAIN_KEYS change, le test force la mise à jour dans le même commit. C'est le workflow voulu.
- **`tests/test_display_explain_hint.py`** — deux tests utilisaient `firewall.inactive` comme exemple de clé de finding qui ne *devait pas* déclencher de hint `--explain` (parce qu'elle n'était pas dans EXPLAIN_KEYS). Maintenant qu'elle y est, ces tests auraient correctement échoué. Le fix remplace l'exemple par une clé fictive `test.nonexistent_key` pour que les tests restent résilients face aux futures additions de EXPLAIN_KEYS.
- **`CHANGELOG.md`** + **`CHANGELOG_FR.md`** — section détaillée v0.4.2 réécrite avec le contenu de la passe de hardening. v0.4.2 avait déjà ce contenu dans `CHANGELOG_FULL.md` ; ceci met la version courte en cohérence.
- **Bump de version** — `pyproject.toml`, `bob/__init__.py`, trois URLs `$id` de schémas, deux badges README, tous de `0.4.2` → `0.4.3`.

### Tests

4464/4464 — +12 vs v0.4.2. Aucune nouvelle fonction de test ; la croissance du compteur est mécanique parce que `tests/test_explain.py` a trois blocs `@pytest.mark.parametrize("key", EXPLAIN_KEYS)` (vérification title, vérification headers WHY/HOW, vérification ref CIS), et l'ajout de 4 clés à `EXPLAIN_KEYS` produit 12 nouvelles invocations paramétrées.

Validé bout-en-bout manuellement :
- `python3 -m bob --explain firewall.inactive` en anglais et en français affiche le titre, le paragraphe WHY IT IS A RISK, la procédure HOW TO FIX numérotée, et la ref CIS.
- Idem pour `firewall.policy_open`, `firewall.policy_unknown`, `prerequisites.ufw_missing`.
- `bob --explain firewall.logging_off` fonctionne toujours (vérification de régression sur la clé pré-existante).
- `bob --explain list` affiche le groupe renommé "Firewall" avec les 5 clés.

### Reporté à une release ultérieure

Cette release ne change pas le travail Phase 2 reporté. La migration systématique des ~37 checks non-pilotes restants vers `Finding.template_vars` (Phase 2 Option A) reste tracée pour **v0.5.0+**. Le test de progrès de migration Phase 2 (`tests/test_template_vars_migration.py`) continue à rendre cette dette visible.

La matrice CI multi-distros et le PKGBUILD AUR sont aussi toujours reportés — contributions communautaires bienvenues, non bloquants.

---

## [v0.4.2] — 14-05-2026

**Phase 3 de la roadmap distro-ready — discipline packaging.** Cette release ajoute les artefacts dont les mainteneurs distros ont besoin pour packager BOB sans patcher le source. Trois man pages, un paquet source Debian ciblant 3 paquets binaires (`bob-core` / `bob-tui` / `bob` meta), une spec RPM Fedora, un profil AppArmor, un threat model `SECURITY.md`, et une politique formelle de support Python. Un audit agent pré-release a aussi fait remonter 2 critiques + 5 importants + 4 mineurs + 1 suggestion — tous corrigés dans la même release (section "Passe de hardening" ci-dessous). 4452/4452 tests (+3 depuis `tests/test_template_vars_migration.py`).

L'intention stratégique : BOB a franchi le cap "est-ce assez stable ?" en Phases 1 & 2. Le dernier obstacle à l'adoption distro est l'absence des artefacts standards que chaque mainteneur distro s'attend à trouver upstream. Cette release ferme ce trou.

---

### `SECURITY.md` — threat model et politique de disclosure

**Fichiers :** `SECURITY.md` (nouveau)

#### Problème

Jusqu'à v0.4.2, la posture sécurité de BOB était implicite. Un packager distro lisant le repo n'avait aucune réponse formelle à : qui est l'adversaire ? Contre quelles menaces BOB défend ? Qu'est-ce qui est hors scope ? Où signaler une vulnérabilité ? Sans ces réponses, les packagers soit devinent (dangereux), soit passent leur chemin (pire).

#### Implémentation

`SECURITY.md` (~150 lignes) couvre :

- **Tableau des versions supportées** avec politique EOL : seul le minor courant reçoit des patches sécurité.
- **Canal de signalement** : `cedricclauzel@mailo.com` avec préfixe `[BOB security]`. Acquittement 7 jours, fenêtre fix 30 jours pour les issues haute-sévérité.
- **Threat model** : ce qu'est BOB (outil audit-only invoqué par utilisateur privilégié) vs ce qu'il n'est PAS (pas de daemon, pas d'agent remote, pas de défense active).
- **Modèle d'adversaire** : trois hypothèses (utilisateur invoquant trusted, layout filesystem sain, package manager intact). BOB est post-compromission, pas pré-.
- **Tableau frontières de confiance** : config user-contrôlée (JSON Schema + ANSI sanitization + size limits), contenu fichiers système (bounded reads, `_C_LOCALE_ENV`), sortie subprocess (timeouts partout, pas de `shell=True` hors `--fix`).
- **Hors scope** : compromission root préalable, attaques niveau noyau, vulnérabilités applicatives.
- **Contrat mode `--fix`** : jamais d'exécution sans confirmation `y`.
- **Avertissement plugins** : `~/.config/bob/checks.d/*.py` ne sont PAS sandboxés.
- **Surface réseau** : 2 appels HTTPS sortants, tous deux gatés par `--offline`. Pas de télémétrie.
- **Manipulation de données** : permissions fichiers, comportement `chown_to_sudo_user` depuis v0.3.6.
- **Recommandations defense-in-depth pour packagers** : profil AppArmor en mode complain par défaut ; `pipx` comme chemin d'install recommandé.
- **Politique de disclosure** : embargo 30 jours extensible, contributeurs crédités sauf demande d'anonymat.

#### Notes de design

- La liste "ce que BOB n'EST PAS" est intentionnellement explicite. Les outils d'audit sont parfois mal classés comme défenses ; clarifier la frontière d'emblée évite les malentendus.
- Le tableau frontières de confiance map chaque traversée à la mitigation côté code déjà en place — ce ne sont pas des promesses aspirationnelles mais des checks que la suite de tests valide déjà.

---

### Man pages

**Fichiers :** `man/bob.1` (nouveau, ~280 lignes), `man/bob.conf.5` (nouveau, ~80 lignes), `man/bob-profile.5` (nouveau, ~100 lignes)

#### Problème

Un paquet Debian / Fedora sans man pages échoue les checks `binary-without-manpage` lintian/rpmlint et est plus dur à découvrir avec `man -k`. Jusqu'à v0.4.2 BOB livrait un `--help` mais pas de `man bob`.

#### Implémentation

Trois man pages groff écrites à la main (validées avec `man -l` et `groff -man -Tutf8`) :

- **`bob(1)`** — page user-facing principale. Sections : `NAME`, `SYNOPSIS`, `DESCRIPTION`, `OPTIONS` (sous-groupées par finalité), `EXIT CODES` (contrat API publique stable rappelé ici), `JSON OUTPUT`, `FILES`, `ENVIRONMENT`, `SECURITY`, `SEE ALSO`, `AUTHOR`, `COPYRIGHT`.
- **`bob.conf(5)`** — format fichier config.
- **`bob-profile(5)`** — format fichier profil d'audit.

Écrites à la main plutôt que générées via `argparse-manpage` pour éviter d'ajouter une dépendance de build. Le coût : updates manuels quand la CLI change — mais la CLI fait partie de l'API publique stable depuis Phase 1, peu de changements attendus.

---

### Paquet source Debian

**Fichiers :** `debian/control`, `debian/copyright`, `debian/changelog`, `debian/rules`, `debian/source/format`, `debian/bob-core.install`, `debian/bob-tui.install`, `debian/bob-core.docs`, `debian/bob-core.manpages`, `debian/apparmor.d/bob` (tous nouveaux)

#### Problème

La convention de packaging Debian est un dossier `debian/` à la racine du projet contenant un set strict de fichiers. Sans lui, le downstream Debian est impossible.

#### Implémentation

**Trois paquets binaires déclarés dans `debian/control` :**

| Paquet binaire | Contient | Pourquoi split |
|---|---|---|
| `bob-core` | Pipeline audit, CLI, checks, scoring, JSON, locales, schemas, man pages, SECURITY.md | Tourne headless. Pas de dep curses. Adapté conteneurs, CI, serveurs minimaux. |
| `bob-tui` | Sous-package `bob/tui/` (TUI curses) | Optionnel. Recommandé sur stations de travail, skip sur serveurs headless. |
| `bob` | Meta-package dépendant des deux | `apt install bob` installe tout. |

`Build-Depends` standard `debhelper-compat (= 13)` + `pybuild-plugin-pyproject`. `Rules-Requires-Root: no`.

`Recommends` / `Suggests` sur `bob-core` listent les soft dependencies avec lesquelles BOB intègre au moment de l'audit (`ufw`, `fail2ban`, `rkhunter`, `clamav`, `auditd`, `aide`, `unattended-upgrades`, `smartmontools`, `apparmor`, `fwupd`).

**`debian/copyright`** au format DEP-5 avec stanzas distinctes pour le source, les données curées, les locales, les schemas. Tout MIT ; les références CIS sont notées explicitement comme mappings (pas redistribution du texte standard CIS).

**`debian/rules`** utilise pybuild. Un `override_dh_install` installe les man pages et `SECURITY.md` dans `bob-core`.

**`debian/source/format`** : `3.0 (quilt)`.

**Fichiers split (`bob-core.install`, `bob-tui.install`)** listent les chemins explicites pour que dh_install sache quel module va où.

#### Profil AppArmor

`debian/apparmor.d/bob` (~140 lignes). Livré en mode `complain` par défaut — l'utilisateur opte pour `enforce` après validation sur sa distro/version. Permet :

- read sur `/etc/`, `/proc/`, `/sys/`, `/var/log/`, dirs état package manager
- read+write sur `~/.config/bob/` et `~/.local/share/bob/`
- exec (via `Pix`) d'une whitelist fermée de ~30 outils système
- TCP sortant — le flag `--offline` au niveau application est la gate, pas le profil

#### Notes de design

- **Trois binaires plutôt qu'un.** Un paquet `bob` unique forcerait chaque image serveur / CI à tirer curses pour une TUI jamais utilisée. Split `bob-core` permet aux déploiements headless de rester légers sans désactiver de fonctionnalités.
- **Pourquoi mode complain par défaut pour AppArmor.** BOB exec beaucoup de binaires dont les chemins varient entre distros. Enforce génèrerait de faux denials. Complain laisse l'utilisateur observer puis graduer.

---

### Spec RPM pour Fedora COPR

**Fichiers :** `packaging/rpm/bob.spec` (nouveau)

#### Problème

Les conventions de packaging Fedora divergent de celles Debian : un seul `.spec`, `pyproject-rpm-macros`, pas de dossier `debian/`, pas de split Python core/extras typique. Sans spec, l'adoption Fedora COPR / RHEL EPEL est impossible.

#### Implémentation

Un paquet binaire `bob` unique sur Fedora (pas de split). La spec utilise `pyproject_wheel` / `pyproject_install` / `pyproject_save_files bob` pour déléguer au pipeline `pyproject.toml`.

`%check` exécute le smoke test plus la suite pytest complète. Sur Fedora COPR, ça attrape toute régression induite par le packaging.

Man pages et `SECURITY.md` installés via `install -D` explicites pendant `%install`.

`Recommends` et `Suggests` miroirent le control Debian avec les noms de paquets Fedora (`firewalld` vs `ufw`, `audit` vs `auditd`).

#### Notes de design

- **Pourquoi un répertoire `packaging/rpm/` séparé.** La convention Debian met tout sous `debian/`. RPM n'a pas d'équivalent racine — `packaging/` garde les deux systèmes visiblement séparés tout en restant upstream.
- **Pas de lignes `Patch:`.** La spec build upstream tel quel.

---

### Politique de support Python

**Fichiers :** `DOCUMENTS/README_TECH.md` + FR — nouvelle section

#### Problème

Les mainteneurs distros planifiant leurs fenêtres de compatibilité Python ont besoin de savoir si BOB supportera Python 3.10 dans 2 ans. Sans politique formelle, chaque EOL Python devient une renégociation.

#### Implémentation

Nouvelle section "Politique de support Python" dans `README_TECH.md` (et FR) s'engage sur **N et N-2** où N est la stable upstream actuelle. À partir de v0.4.2 :

| Python | Statut |
|---|---|
| 3.13 | ✅ supporté (à sortie) |
| 3.12 | ✅ CI par défaut |
| 3.11 | ✅ supporté |
| 3.10 | ✅ le plus ancien |
| 3.9 | ❌ EOL depuis v0.2.3 |

Procédure d'abandon s'étale sur au moins 3 minor BOB releases (valider / annoncer / retirer) pour préavis minimum 6 mois. Miroir des cycles freeze Debian / Fedora.

---

### Tests

4452/4452 — +3 vs v0.4.1, tous issus de `tests/test_template_vars_migration.py` (S1) qui rend visible la dette de migration Phase 2. La passe de hardening (C1, C2, I1-I5, M1-M5, S2, S3) a modifié 11 fichiers Python ; la suite existante couvrait tous ces fichiers et est restée verte tout du long.

Validation séparée :
- `groff -man -Tutf8` et `man -l` parsent les 3 man pages sans erreur.
- Les 3 fichiers schema JSON chargent et valident via `jsonschema`.

---

### Contexte roadmap

| Phase | Statut |
|---|---|
| Phase 1 (contrats) | ✅ v0.4.0 |
| Phase 2 (découplage archi) — Option B additive | ✅ v0.4.1 |
| Phase 2 — Option A breaking | ⏳ v0.5.0+ |
| **Phase 3 (discipline packaging)** | **✅ v0.4.2** |
| Phase 3 finitions (CI multi-distro, PKGBUILD AUR) | ⏳ contributions communautaires v0.4.x |

Après v0.4.2, BOB est **packaging-complet** pour le chemin AUR/COPR et **prêt pour Debian unstable** sous réserve de validation lintian-clean + parrainage upstream.

---

### Hardening pass — audit pré-release

**Fichiers :** `bob/checks/firewall.py`, `bob/checks/ssl_certs.py`, `bob/checks/virtualization.py`, `bob/_paths.py`, `bob/i18n.py`, `bob/registry.py`, `bob/watch.py`, `bob/__main__.py`, `bob/compare.py`, `bob/formatter.py`, `man/bob.1`, `debian/apparmor.d/bob`, `packaging/rpm/bob.spec`, `tests/test_template_vars_migration.py` (nouveau), `microsoft.gpg` (supprimé)

#### Problème

Un audit complet pré-release (agent general-purpose, ~3500 lignes source consultées) a fait remonter **2 critiques + 5 importants + 4 mineurs + 1 suggestion**. Les deux findings critiques se concentraient sur les artefacts de packaging (écrits sans cross-check mécanique vs le code), confirmant que cette catégorie d'artefact mérite la même rigueur que le source.

#### Corrections critiques

**C1 — Findings `firewall.py` sans `key=`** (`bob/checks/firewall.py:154,165,178,183`). Trois appels `result.alert()` (`prerequisites.ufw_missing`, `firewall.inactive`, `firewall.policy_open`) et un `result.add_deduction()` n'avaient pas de `key=`. Conséquence : les alertes max-criticité ne pouvaient être ni `--ignore`ées, ni profilées, ni matchées par les consommateurs JSON (qui utilisent tous `Finding.key` / `Deduction.key`). Fix : ajout de `key=` aux 4 sites + 4 autres findings de la même fonction pour cohérence. (`bob/explain.py` non étendu — ajouter ces 4 clés à `EXPLAIN_KEYS` requiert d'écrire titre/why/how/CIS complets dans `en.json` et `fr.json` pour chacune, **reporté explicitement en v0.4.3** avec un TODO inline près du groupe "Firewall Logging" ; `bob --explain firewall.policy_open` dira "not found" en v0.4.2 mais `--ignore` / profils / matching JSON fonctionnent correctement.)

**C2 — Profil AppArmor incomplet + mauvais chemin** (`debian/apparmor.d/bob`). 10 binaires que BOB exec étaient absents du profil (`df`, `lsblk`, `dpkg-query`, `getenforce`, `apt-get`, `find`, `ps`, `netstat`, `ntpstat`, `docker`) — en mode `enforce`, les checks disk/SUID/MAC/updates/SMTP/NTP/docker/desktop-apps retournaient tous vide. De plus, la ligne 85 déclarait `/usr/local/sbin/bob-*` rw alors que `bob/cron.py:30` écrit dans `/usr/local/bin/bob-{slug}`. Donc `--install-cron` échouerait silencieusement sous enforce. Fix : ajout des 10 binaires manquants + correction du chemin.

#### Corrections importantes

**I1+I2 — `_C_LOCALE_ENV` manquant sur 3 sites subprocess** (`bob/checks/ssl_certs.py:283`, `bob/checks/virtualization.py:166,178`). Le threat model SECURITY.md promet que tous les appels subprocess utilisent `_C_LOCALE_ENV` pour éviter le parsing dépendant de la locale. `openssl x509 -enddate` émettrait "mai 14" sur locale FR qui ferait échouer `datetime.strptime(..., "%b ...")` ; `ip link show` et `snap connections --all` avaient le même risque. Fix : passage de `env=_C_LOCALE_ENV` aux 3 appels.

**I3 — Env var legacy `UFW_AUDIT_SHARE`** (`bob/_paths.py`). Le projet s'appelait "UFW Audit" avant v0.1.0 ; la variable env share-dir avait gardé l'ancien nom. Les packagers étaient confus. Renommée en `BOB_SHARE` (le contrat documenté depuis v0.4.2). `UFW_AUDIT_SHARE` reste accepté pour la rétrocompat — quand les deux sont définis, `BOB_SHARE` gagne. Logué en INFO quand seul le nom legacy est utilisé. Documenté dans `man/bob.1` section ENVIRONMENT.

**I4 — RPM `Recommends: firewalld`** (`packaging/rpm/bob.spec`). BOB lit `ufw status` exclusivement — recommander `firewalld` était un guess côté Fedora qui induirait en erreur les packagers. Corrigé en `Recommends: ufw` avec commentaire explicatif inline.

**I5 — `bob/watch.py` ne thread pas `user_config`** (ligne 80-83). Le mode `--watch` perdait silencieusement la whitelist SUID de l'utilisateur car `run_checks()` était appelé sans `user_config=`. Whitelist `[]` à chaque tick → faux positifs SUID répétés. Fix : thread `user_config` à travers `run_watch()` depuis `__main__.py`.

#### Corrections mineures

- **M1** — Suppression de `microsoft.gpg` untracked (résidu d'`apt-add-repository` à la racine du repo).
- **M2** — Clarification du docstring `bob/formatter.py` : "Status: this module is a public API for external integrators. No production code path in BOB itself calls format_finding / format_deduction in v0.4.x." Lève l'ambiguïté que le formatter serait le chemin de rendu interne.
- **M4** — Exposition de `bob.compare.BASELINE_PATH` (sans underscore) comme symbole public ; `_BASELINE_PATH` conservé comme alias transitionnel. `bob/__main__.py` mis à jour pour utiliser le nom public.
- **M5** — Ajout `Suggests: apparmor`, `Suggests: apparmor-utils` à la spec RPM pour symétrie avec le paquet Debian.

#### Suggestion implémentée

**S1 — `tests/test_template_vars_migration.py`** (nouveau, 3 tests) : track la dette de migration Phase 2 de manière visible. Le set actuel `_MIGRATED_CHECKS_V0_4_2` est `{ssh.py, hardening.py, firewall.py}` — quand de nouveaux checks gagnent des `template_vars=`, le set est mis à jour dans le même commit. Une régression qui retirerait accidentellement `template_vars` d'un check migré échoue le CI immédiatement.

#### Tests

4449 → **4452** (+3 du nouveau test de migration). Tous les tests existants restent verts.

#### Note qualité finale : 8.5/10 → 9/10

L'audit pré-release a fermé le gap entre les promesses SECURITY.md et la réalité du code, corrigé les 2 vrais bugs du chemin runtime (C1 et I5 — tous deux à conséquence utilisateur visible), et aligné les artefacts de packaging avec le source. Le travail restant vers 10/10 est la migration systématique des 37 checks non-pilotes vers `template_vars`, explicitement multi-release et tracée par le nouveau test.

---

## [v0.4.1] — 14-05-2026

**Phase 2 de la roadmap distro-ready — découplage architectural.** Trois zones traitées : finalisation `--offline`, isolation curses sous `bob/tui/`, et représentation findings/deductions indépendante de la locale via `template_vars` additif. Plus une passe de hardening post-revue sur `bob/formatter.py` (API resserrée, tests edge-case). Tous les changements sont non-breaking (additifs). 4449/4449 tests (+19).

La roadmap Phase 2 vise un paquet Debian `bob-core` installable sans curses et sans texte localisé enfoui dans la sortie JSON. Cette release pose les fondations sans casser l'API existante.

---

### Zone 2.1 — Mode `--offline` strict finalisé

**Fichiers :** `tests/test_webhook.py`

#### Problème

Le flag `-o` / `--offline` existe depuis v0.4.0 et gatait déjà les deux sites touchant le réseau (`bob.sysinfo.get_public_ip` HTTP, `bob.webhook.send_webhook` POST). Manquait pour un vrai audit distro-ready : un inventaire bout en bout de tous les appels qui pourraient toucher le réseau, et des tests d'intégration qui figent le contrat.

#### Implémentation

Audit réseau (survey only, pas de modif de code) :

| Site | Verdict |
|---|---|
| `bob/sysinfo.py:158` `urllib.request.urlopen` (`get_public_ip`) | ✅ gaté par `offline=True` |
| `bob/webhook.py:send_webhook` POST HTTP | ✅ gaté par `__main__.py:277` |
| `bob/checks/kernel_modules.py` `apt-cache policy` | ✅ lecture cache local |
| `bob/checks/firmware.py` `fwupdmgr get-updates` | ✅ lecture cache local |
| `bob/checks/auth_log.py` `journalctl` | ✅ local |
| `bob/checks/ssl_certs.py` `openssl x509 -in <file>` | ✅ fichier local |
| Autres (`ss`, `iptables`, `nft`, …) | ✅ tous locaux |

Conclusion : aucun site réseau oublié, le plumbing `--offline` est complet.

3 nouveaux tests dans `tests/test_webhook.py` qui figent le contrat (CLI parse OK, webhook skip, urllib short-circuit).

#### Notes de design

Pourquoi un test miroir de la branche de décision plutôt qu'un test d'intégration full `_run()` : l'orchestration pipeline tire des dizaines de dépendances (FS, subprocess, locale, ScoreEngine, …). Mirorer la condition à 2 lignes donne la même couverture pour une fraction du coût de maintenance.

---

### Zone 2.2 — Sous-package curses `bob/tui/`

**Fichiers :** nouveau `bob/tui/__init__.py`, `bob/cron_ui.py` → `bob/tui/cron.py` (git mv), `bob/cron.py` (sites d'import), `DOCUMENTS/README_DEV.md` (FR + EN)

#### Problème

Pour un paquet Debian `bob-core` qui tourne dans des conteneurs minimaux (sans curses), le reste de `bob.*` doit rester importable sans curses installé. Les `import curses` étaient déjà lazy (à l'intérieur des fonctions) mais `bob/cron_ui.py` vivait au top-level de `bob.*`, suggérant qu'il faisait partie du module core. Un packager lisant la structure du projet ne pouvait pas dire que `cron_ui` était optionnel.

#### Implémentation

- Nouveau `bob/tui/__init__.py` documente la politique du sous-package.
- `git mv bob/cron_ui.py bob/tui/cron.py` (historique préservé).
- `bob/cron.py` : 2 sites d'import lazy updates, docstring module ajusté.
- `setuptools.packages.find` config (`include = ["bob*"]`) couvre déjà `bob.tui` automatiquement — pas de changement `pyproject.toml`.
- `DOCUMENTS/README_DEV.md` + FR : arbre de structure mis à jour.

#### Notes de design

- **Pourquoi un sous-package plutôt qu'une distribution séparée.** Le split en `bob-core` + `bob-tui` sur PyPI est une préoccupation de packaging, pas de code. La distribution `bob` continue à tout livrer ; le layout sous-package est la fondation pour qu'un futur packager Debian puisse split sans toucher au code.
- **`explain.py`, `manage_logs.py`, `cron.py` non déplacés.** Mélangent logique métier et bits TUI. Out of scope.

---

### Zone 2.3 — Findings indépendants de la locale via `template_vars` additif

**Fichiers :** `bob/scoring.py`, `bob/json_output.py`, nouveau `bob/formatter.py`, `bob/checks/ssh.py`, `bob/checks/hardening.py`, `bob/checks/firewall.py`, nouveau `tests/test_formatter.py`, `tests/test_json_schema.py`

#### Problème

Jusqu'à v0.4.0, `Finding.message` et `Deduction.reason` étaient des strings déjà formatées dans la locale active. Les consommateurs externes du JSON n'avaient aucun moyen de :
- Rendre le même finding dans une autre locale.
- Matcher les findings par leur clé sémantique stable sans parser la chaîne localisée.

`Finding.key` (ajouté en Phase 1) donnait un nom stable, mais les variables interpolées dans le template étaient perdues. Un client voulant "la liste des ciphers signalés comme faibles" devait parser le `message` localisé.

L'objectif Phase 2 est `bob.core` *pur* — sans `print()`, sans `_t()`, sans curses. Cette release pose le premier pas additif : exposer `(key, template_vars)` partout en parallèle du legacy `message`/`reason`.

#### Implémentation

##### Deux nouveaux champs dataclass

```python
@dataclass
class Deduction:
    ...
    template_vars: dict = field(default_factory=dict)   # NOUVEAU

@dataclass
class Finding:
    ...
    template_vars: dict = field(default_factory=dict)   # NOUVEAU
```

Le nom `template_vars` est délibéré : il documente que le dict contient les variables passées à `.format(**kwargs)` du template i18n. Nous avons évité `context` (déjà pris par `Deduction.context: str` signifiant le scope réseau) et `vars`/`params` (trop générique).

##### Helpers de convenance acceptent `template_vars=`

`CheckResult.add_finding`, `.ok`, `.info`, `.warn`, `.alert`, `.add_deduction` gagnent tous un kwarg optionnel `template_vars=None`. Les sites d'appel legacy ne nécessitent ZÉRO changement.

##### Nouveau module `bob.formatter`

`format_finding(finding, lang=None) -> str` et `format_deduction(deduction, lang=None) -> str` implémentent le rendu indépendant de la locale. Ordre de résolution :

1. Si `key` est défini ET `template_vars` non-vide → render `_t(key, **template_vars)`.
2. Si `key` défini sans template_vars → render `_t(key)` si la résolution est clean.
3. Sinon fallback sur `finding.message` / `deduction.reason` (chemin legacy).

Le fallback à l'étape 3 rend le formatter 100% rétrocompatible.

Le paramètre `lang` est réservé pour une future API permettant de rendre le même finding dans plusieurs locales sans flipper la locale du processus.

##### Trois checks pilotes migrés

- **`bob/checks/ssh.py`** — `_check_host_keys` (4 sites) avec `template_vars={"name": ..., "bits": ..., "type": ...}` selon le cas.
- **`bob/checks/hardening.py`** — `tcp_syncookies_ok` avec `value=snapshot.tcp_syncookies`.
- **`bob/checks/firewall.py`** — `firewall.logging_ok` et `logging_verbose` avec `level=level`.

Dans chaque cas, le `message=_t("key", **vars)` existant est préservé (compat) et `template_vars={...vars...}` ajouté en parallèle.

##### `template_vars` exposé dans la sortie JSON

`bob/json_output.py` sérialise désormais `template_vars` sur chaque deduction et chaque finding (full mode) :

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

Le champ est toujours présent (dict vide pour les checks legacy). C'est additif.

#### Tests

`tests/test_formatter.py` (nouveau, 10 tests) : ordre de résolution, roundtrip locale, rétrocompatibilité.
`tests/test_json_schema.py` (+2) : exposition `template_vars` dans le JSON.
`tests/test_webhook.py` (+3) : contrat offline (couvert en Zone 2.1).

Total : **+15 tests** (4430 → 4445).

#### Notes de design

- **Option B vs Option A.** Option B = additive, pas de breaking, ce que cette release livre. Option A (breaking : suppression de `message`, `template_vars` obligatoire) reportée à v0.5.0+ quand les 40 checks auront été migrés et que le schéma JSON pourra livrer un v2.
- **Pourquoi 3 pilotes, pas les 40 d'un coup.** Migration mécanique ~500 lignes — possible mais error-prone. Le pattern est documenté via les pilotes ; le reste peut venir incrémentalement (v0.4.2, v0.4.3, …).
- **Dict vide ≠ None.** Choix de `field(default_factory=dict)` plutôt que `Optional[dict]` pour uniformité JSON.

---

### Hardening passe — revue de `bob/formatter.py`

**Fichiers :** `bob/formatter.py`, `bob/i18n.py`, `tests/test_formatter.py`

#### Problème

Une revue post-implémentation de `formatter.py` (analyse ChatGPT externe demandée par l'utilisateur) a relevé quatre problèmes d'API/architecture légitimes sur un module qui s'apprête à devenir un contrat public stable pour les packagers downstream :

1. **Paramètre `lang=` mensonger.** `format_finding(finding, lang=None)` exposait un override de locale qui était un no-op silencieux (`_ = lang` — l'état global `bob.i18n.t()` gagnait toujours). Les appelants externes passant `lang="fr"` obtiendraient toujours la locale du process sans aucune indication. Piège pour les packagers distros qui piperaient les sorties dans leur propre pipeline.
2. **Détection fragile de clé manquante via `startswith("[")`.** `_render_key` retournait `"[key]"` (sentinelle `bob.i18n.t()` pour clés absentes) et l'appelant vérifiait `startswith("[")` pour la détecter. Couple le formatter à une convention `t()` non documentée ; un changement futur de cette sentinelle casserait silencieusement le formatter.
3. **`except (KeyError, TypeError, ValueError)` trop large.** Catcher `TypeError` et `ValueError` masque de vrais bugs Python (e.g. changement d'API `_t()`). Ne devrait swallow que ce qui est vraiment attendu (mismatch de placeholder depuis `str.format`).
4. **Le mot "reproducible" dans la docstring sur-promet** ce que le module peut livrer alors que ~40 checks utilisent encore le chemin legacy `message=`-only.

#### Implémentation

1. **Paramètre `lang=` supprimé** (Option A de la revue). Le réintroduire quand `bob.i18n` deviendra pur (v0.5.x avec l'extraction complète `bob.core`) est préférable à garder une signature mensongère aujourd'hui. La signature pour v0.4.1 est désormais `format_finding(finding) -> str` et `format_deduction(deduction) -> str`.

2. **Nouveau `bob.i18n.try_t(key, **kwargs) -> str | None`** ajouté : détection clean de clé manquante sans parser la sentinelle `"[key]"`. Comportement :
   - Retourne `None` pour les clés absentes (dans la locale active et le fallback EN).
   - Retourne la string rendue en cas de succès.
   - Propage `KeyError` depuis `str.format()` quand un placeholder requis est manquant — responsabilité de l'appelant, pas une dégradation runtime.
   Le legacy `bob.i18n.t()` continue de retourner `"[key]"` pour le reste du codebase qui s'appuie sur ce contrat ; seul `formatter` utilise la nouvelle fonction.

3. **Gestion des exceptions resserrée dans `_try_render`** : plus de catch-all. `try_t` retourne `None` proprement pour les clés manquantes ; `KeyError` depuis `str.format()` (placeholder manquant = bug côté check) propage afin que le bug surface immédiatement au lieu de se dégrader silencieusement vers `finding.message`.

4. **Docstrings réécrites** : "reproducible" → "progressively reconstructible" + une section "Current state (v0.4.1)" précisant exactement ce qui est reproductible aujourd'hui et ce qui ne l'est pas. Le couplage entre `Finding.key` / clé `--explain` / clé i18n / clé de matching JSON (= un ABI textuel) est désormais explicitement reconnu avec un pointeur vers la freeze policy de `bob/explain.py`.

#### Tests

`tests/test_formatter.py` étendu de 10 à 14 tests (+4 dans la nouvelle classe `TestFormatterEdgeCases`) :

| Test | Couverture |
|---|---|
| `test_empty_template_vars_with_placeholder_template_returns_raw` | Edge case : `template_vars` vide + clé dont le template a des placeholders → template brut retourné avec `{placeholders}` littéraux intacts (cohérent avec `i18n.t()`, fait surface le bug visuellement) |
| `test_partial_template_vars_raises_keyerror` | `template_vars` non-vide manquant un placeholder requis → `KeyError` propage (pas de fallback silencieux) |
| `test_mismatched_key_vs_message_uses_key` | Le chemin key gagne quand il résout proprement, même si `message` dit autre chose (la représentation structurée fait autorité une fois populée) |
| `test_empty_finding_message_with_no_key` | Retourne `""` (pas `None`) quand ni key ni message n'est défini — préserve le contrat documenté "retourne toujours une string" |

Décompte total des tests v0.4.1 : **4445 → 4449** (+4 depuis la passe de hardening).

#### Notes de design

- **Pourquoi faire surface `KeyError` au lieu de fallback sur `message`.** Un placeholder manquant signifie que le check a déclaré une key dont le template a besoin d'une variable que le check n'a pas fournie. Utiliser silencieusement `finding.message` masquerait un bug côté check et laisserait les clients sans signal. Lever l'exception force le bug à être visible dans la suite de tests où il devrait être attrapé.
- **Pourquoi `try_t` et pas refactoriser `t()`.** Le legacy `t()` retournant `"[key]"` est utilisé partout dans le codebase pour "afficher mais ne pas crasher". Changer son contrat de retour ricocherait sur 600+ sites d'appel. Ajouter `try_t` comme fonction sœur donne au formatter un signal clé-manquante clean sans perturber la sémantique existante.
- **Pourquoi retirer `lang=` plutôt que le fixer.** Implémenter proprement le switch de locale par appel nécessite de rendre `bob.i18n` réentrant (objet instance plutôt qu'état module-level) — travail qui appartient à v0.5.x avec le refactor complet `bob.core`. Exposer un paramètre aujourd'hui qui ment sur son implémentation est pire que ne pas l'exposer.

---

### Contexte roadmap

Après v0.4.1, le plan Phase 2 est :

| Item | Statut |
|---|---|
| 2.1 `--offline` strict | ✅ fait (vérifié + testé) |
| 2.2 isolation curses (`bob/tui/`) | ✅ fait (cron_ui déplacé) |
| 2.3 découplage core/i18n — Option B (additive) | ✅ fait (3 pilotes + formatter + JSON) |
| 2.3 découplage core/i18n — Option A (breaking) | ⏳ v0.5.0+ |
| Vague 2 schéma (typed ports, `port_resolution`) | ⏳ v0.5.0+ |
| Phase 3 (man pages, debian/, profil AppArmor, SECURITY.md) | ⏳ futur |

---

## [v0.4.0] — 14-05-2026

Phase 1 de la roadmap distro-ready (voir mémoire `project_distro_roadmap`) — cinq contrats d'API publique figés pour que scripts, dashboards et packagers downstream puissent s'appuyer sur un comportement stable entre versions. Aucune nouvelle fonctionnalité, aucun changement breaking — additif uniquement. 4405/4405 tests (+57). Plus un petit correctif UX sur l'affichage du score inchangé.

Cibles de la roadmap par ordre de difficulté :
- AUR / COPR communautaire — viable maintenant
- Debian unstable / Fedora COPR officiel — ~6 mois post-v0.4.0
- Debian main / Fedora main — 12–18 mois minimum (nécessite stabilité soutenue des contrats)

Cette release coche les 5 premières cases de la Phase 1 : codes de retour, fallback locale, contrat de sortie JSON, freeze des clés `--explain`, schéma de plugins. La Phase 2 (découplage architectural : `bob.core` pur, `bob.tui` isolé, `--offline` strict) est la prochaine étape.

---

### Contrat stable — Codes de retour documentés comme API publique

**Fichiers :** `bob/__main__.py`, `bob/cli.py`, `DOCUMENTS/README_TECH.md` (FR/EN)

#### Problème

Les 5 codes de retour (`0`/`1`/`2`/`3`/`4`) étaient définis comme constantes dans `bob/__main__.py` et utilisés de façon cohérente dans `_run()`, mais sans statut formel d'API. Le texte `--help` documentait `0`/`1`/`2`/`3` mais **omettait `4`** (`EXIT_TARGET_MISSED`). README_TECH avait un tableau mais ne promettait pas de stabilité.

Les scripts externes (pipelines CI, wrappers cron, agents de monitoring) ont besoin d'un contrat : la valeur et le sens d'un code ne doit pas dériver entre versions.

#### Implémentation

- Ajout d'un bloc docstring "STABLE PUBLIC API" au-dessus des constantes de codes de retour, énonçant explicitement qu'ils font partie du contrat public de BOB — pas de suppression, pas de glissement sémantique au sein d'une version majeure, ajouts seulement.
- Ajout du `4` manquant dans `--help` (section "EXIT CODES") avec un pointeur vers README_TECH.
- Promotion de la section README_TECH : ajout d'un bloc citation énonçant la promesse de stabilité, tableau étendu avec les noms de constantes (`EXIT_OK`, …), et snippet de code montrant comment les importer programmatiquement.
- Miroir dans README_TECH_FR.

Les 18 tests existants dans `tests/test_exit_codes.py` verrouillent déjà les valeurs et la logique de décision — ils servent désormais d'application du contrat.

#### Notes de design

La décision de code de sortie de `_run()` (target → alerts → warnings → ok) est testée unitairement via `_decide_exit()`, une copie fidèle isolée du pipeline d'audit. C'est le mapping canonique : tout futur changement doit mettre à jour les deux copies et faire évoluer les tests délibérément.

---

### Contrat stable — Détection automatique de la locale via POSIX `$LANG`

**Fichiers :** `bob/i18n.py`, `bob/cli.py`, `tests/conftest.py`, `tests/test_i18n.py`, `tests/test_cli.py`, `bob/cli.py` (--help), `DOCUMENTS/README_TECH.md` (FR/EN)

#### Problème

L'interface de BOB par défaut était l'anglais sauf si `--french` ou `--lang=fr` était passé explicitement. Tout autre outil Unix (`man`, `git`, `apt`, `gcc`, …) honore automatiquement `$LANG` / `$LC_*`. Un utilisateur français tapant `sudo bob` obtenait l'anglais ; surprenant et non-conforme aux attentes POSIX.

Pour le packaging distro, c'est encore plus important : un paquet Debian livrant BOB doit s'intégrer harmonieusement avec la locale système. Un utilisateur avec `LANG=fr_FR.UTF-8` doit obtenir une sortie française sans gymnastique de flags.

#### Implémentation

Nouvelle fonction `bob.i18n.detect_system_lang() -> str` :

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

L'ordre de probe correspond à POSIX (`LC_ALL` prime sur `LC_MESSAGES` qui prime sur `LANG`). Les valeurs vides retombent sur le candidat suivant. `C` / `POSIX` / `C.UTF-8` / langues non supportées → fallback sur `DEFAULT_LANG = "en"`.

`bob.cli.parse_args()` suit désormais si l'utilisateur a passé `--lang=` / `--french` via un flag local `lang_explicit`. Après le parsing argv, si le flag est encore `False`, `config.lang = detect_system_lang()`. Les flags explicites priment toujours — la détection est un défaut, pas un override.

`tests/conftest.py` (nouveau) : une fixture autouse définit `LC_ALL=C`/`LANG=C` avant chaque test, afin que les défauts CLI dépendants de la locale se résolvent prévisiblement, indépendamment de la locale hôte du dev. Les tests qui ont besoin d'une locale spécifique la définissent explicitement avec `monkeypatch.setenv()`.

#### Tests

- 12 nouveaux tests dans la classe `TestDetectSystemLang` : env vide, `C`, `POSIX`, `C.UTF-8`, `fr_FR.UTF-8`, `fr_BE`, `fr_FR@euro`, `en_US.UTF-8`, non supportés `ja_JP`/`de_DE`/`es_ES`/`zh_CN`, override par `LC_ALL`, override par `LC_MESSAGES`, `LC_ALL` vide retombe.
- 4 tests d'intégration dans `tests/test_cli.py` : `--french` override la locale système, `--lang=en` override la locale système, default utilise `fr` quand la locale système est française, default utilise `en` quand `LANG=C`.

#### Notes de design

La décision de défaut sur la locale système (au lieu de toujours `en`) est une amélioration UX, pas un breaking change pour un contrat documenté — `--lang=en` continue de fonctionner et force l'anglais explicitement. Le changement est documenté dans `--help` ("default: detected from $LANG, fallback en") et dans les deux variantes README_TECH. Les CI/scripts existants qui ne définissent pas `LC_ALL` ne voient aucun changement parce que `LANG=C` retombe sur `en`.

---

### Contrat stable — Schéma de sortie JSON documenté + champ `key` exposé

**Fichiers :** `bob/json_output.py`, `tests/test_json_schema.py` (nouveau), `DOCUMENTS/README_TECH.md` (FR/EN)

#### Problème

La sortie `--json` avait `"schema_version": "1"` depuis v0.2.x mais sans contrat formel : les clés top-level pouvaient disparaître ou être renommées sans préavis, le schéma n'avait aucun test d'enforcement, et les clients devaient matcher les findings via les chaînes `message` / `reason` localisées (qui diffèrent entre `en` et `fr`).

Pour l'adoption distro c'est un blocage : un dashboard packagé Debian parsant la sortie BOB ne peut pas être attendu de switcher la logique de matching par locale, ni survivre à une dérive silencieuse du schéma entre releases BOB.

#### Implémentation

Ajout d'un docstring de stabilité en tête de `bob/json_output.py` formalisant les règles :

> - Les clés top-level ne disparaissent jamais, ne sont jamais renommées, ne changent jamais de sémantique au sein d'une même version majeure de `schema_version`.
> - De nouvelles clés top-level PEUVENT être ajoutées dans n'importe quelle release ; les clients doivent ignorer les clés inconnues.
> - Les dicts imbriqués suivent la même règle.
> - Les changements breaking incrémentent `schema_version` à un nouveau majeur (`"2"`, `"3"`…).

Deux nouvelles constantes module-level rendent le contrat testable :

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

Ajout de `"key": d.key` à chaque entrée `deductions[]` et `"key": f.key` à chaque entrée `findings[]`. Ce sont des clés i18n stables en notation pointée (`firewall.logging_off`, `ssh.password_auth`, …) qui ne changent jamais entre locales et ne sont jamais renommées sans entrée d'alias — les clients doivent matcher sur `key`, pas sur `reason`/`message`.

`DOCUMENTS/README_TECH.md` (et FR) gagnent une section complète "Schéma de sortie JSON" : promesse de stabilité citée, tableau complet des clés top-level avec types et descriptions, structure de `deductions[]` / `domain_scores` / clés full-mode, exemple de matching indépendant de la locale avec `jq`.

#### Tests

`tests/test_json_schema.py` (nouveau, 15 tests, 4 classes) :

- `TestSchemaVersion` — schema_version est une string, actuellement `"1"`.
- `TestRequiredKeysAlwaysPresent` — clés requises en mode short et full, aucune clé full-only ne fuit en mode short.
- `TestFieldTypes` — `score`/`score_max`/`alerts`/`warnings` sont int, `risk` est string, `timestamp` est ISO 8601.
- `TestStableKeysExposed` — chaque deduction et finding a un champ `key`, format dotted-path.
- `TestDomainScoresStructure` — `domain_scores` est un dict-of-dicts avec `score` (int) et `label` (str).

#### Notes de design

L'exposition du champ `key` est la fondation du découplage architectural Phase 2 : une fois `Finding.message` découplé de `_t()` (planifié dans la prochaine phase), la sortie JSON deviendra entièrement indépendante de la locale — les clients pourront formater eux-mêmes les messages depuis les clés.

---

### Contrat stable — Alias map `--explain` + politique de freeze

**Fichiers :** `bob/explain.py`, `tests/test_explain.py`

#### Problème

Les 112 clés `--explain` (e.g. `ssh.password_auth`, `firewall.logging_off`, `kernel_hardening.aslr_disabled`) sont aussi utilisées comme `Finding.key` et `Deduction.key` — elles forment un namespace public sur lequel scripts et dashboards matchent. Renommer une clé était un breaking change silencieux.

#### Implémentation

Ajout d'une section explicite "STABLE PUBLIC API — `--explain` KEY FREEZE POLICY" au docstring du module, énonçant quatre règles : pas de suppression, pas de glissement sémantique, les renommages passent par `EXPLAIN_KEY_ALIASES`, ajouts libres.

Introduction de `EXPLAIN_KEY_ALIASES: dict[str, str]` comme mécanisme de migration pour les renommages. Vide pour l'instant — aucune clé n'a encore été renommée. La map existe pour qu'un futur renommage ait un chemin documenté et testé : ajouter `"old_name": "new_name"` ici et les clients appelant `bob --explain old_name` (ou matchant `Finding.key == "old_name"` en JSON) continuent de fonctionner indéfiniment.

`normalize_key()` étendue pour consulter la map d'alias après le strip des segments de chemin :

```python
def normalize_key(key: str) -> str:
    m = _NORMALIZE_RE.match(key)
    if m:
        key = f"{m.group(1)}.{m.group(2)}"
    return EXPLAIN_KEY_ALIASES.get(key, key)
```

#### Tests

6 nouveaux tests dans `tests/test_explain.py` :

- `TestExplainKeyAliases` (5 tests) : la map d'alias est un dict, les cibles d'alias sont des clés canoniques valides, les clés d'alias ne sont PAS dans le set canonique (pas d'overlap), `normalize_key()` résout les alias, passthrough sans alias.
- `TestExplainKeyFreezePolicy` (1 test) : un sous-ensemble figé de 16 clés load-bearing (`ssh.password_auth`, `ssh.permit_root_login`, `firewall.logging_off`, `kernel_hardening.aslr_disabled`, …) doit toujours être dans `EXPLAIN_KEYS` — l'échec pointe soit vers leur restauration, soit vers l'enregistrement d'un alias.

#### Notes de design

La politique de freeze est intentionnellement par clé (pas par groupe) : les groupes peuvent être réorganisés dans `_EXPLAIN_GROUPS` sans casser de contrat, seules les clés individuelles sont sticky.

---

### Contrat stable — JSON Schema formel pour les plugins services

**Fichiers :** `bob/data/schemas/service.schema.json` (nouveau), `bob/data/schemas/services-list.schema.json` (nouveau), `pyproject.toml`, `bob/registry.py`, `tests/test_services_schema.py` (nouveau), `DOCUMENTS/README_TECH.md` (FR/EN)

#### Problème

Les définitions de services (`bob/data/services.json` + plugins utilisateur dans `~/.config/bob/services.d/`) avaient un validateur fait main dans `Service.from_dict()` (Python uniquement, distribué sur 36 lignes). Les packagers de distro et auteurs de plugins n'avaient aucun contrat machine-readable : les règles (champs requis, regex pour les ports, enum pour le risk, règles d'identifier pour `config_key`) devaient être reverse-engineerées depuis le code Python ou par essai-erreur.

#### Implémentation

Deux fichiers JSON Schema Draft 2020-12 :

- **`service.schema.json`** décrit une seule entrée service (le dict passé à `Service.from_dict()`) :
  - `additionalProperties: false` (aucun champ inconnu)
  - 7 champs requis (`id`, `label`, `packages`, `services`, `ports`, `risk`, `config_key`)
  - Patterns stricts : `id` est `^[a-zA-Z][a-zA-Z0-9_-]*$`, ports `^[1-9][0-9]{0,4}/(tcp|udp)$`, `config_key` est un identifier Python
  - `risk` est enum `{low, medium, high, critical}`
  - Conditionnel via `allOf` / `if/then` : quand `config_key="fixed"`, `ports` doit avoir `minItems: 1`
  - `detection` (optionnel) avec arrays `binary` / `snap` / `config_files`
- **`services-list.schema.json`** wraps la forme tableau (le fichier `services.json` entier ou un fichier plugin utilisateur).

Schémas livrés via `package_data` afin qu'ils soient disponibles à `bob/data/schemas/*.json` après pip install — n'importe quel tooling externe (`check-jsonschema`, `ajv`, plugins d'IDE) peut valider les plugins utilisateur.

Le validateur Python dans `Service.from_dict()` reste la source de vérité au runtime — **zéro dépendance runtime ajoutée**. Le JSON Schema le reflète pour le tooling externe.

Le docstring de la classe `bob/registry.py` `Service` pointe désormais vers le fichier schéma comme contrat formel.

`DOCUMENTS/README_TECH.md` (et FR) gagne une sous-section "Schéma de plugin de service" avec un exemple complet et l'explication des champs requis vs optionnels. La note antérieure sur la résolution de `Path.home()` vers `/root` est aussi mise à jour pour refléter le fix v0.3.6 `get_user_home()`.

#### Tests

`tests/test_services_schema.py` (nouveau, 20 tests, 5 classes) :

- `TestSchemasAreWellFormed` — les schémas passent l'auto-validation Draft 2020-12, ont `$id`/`title` propres.
- `TestBundledServicesMatchSchema` — `services.json` bundled valide entrée par entrée, IDs uniques.
- `TestValidPluginSamples` — 3 plugins valides échantillons (minimal fixed, avec block detection, user config_key).
- `TestInvalidPluginSamples` — 8 cas de rejet (champ requis manquant, risk invalide, port malformé, port 0, port > 65535 via Python, champ inconnu, fixed sans ports, ID avec espaces, string binary vide).
- `TestSchemaPythonParity` — ce que le schema accepte est aussi accepté par `Service.from_dict()`, ce qui échoue Python est aussi attrapé par le schema.

`jsonschema` est une dépendance test-only, pas runtime — utilise `pytest.importorskip` pour que le fichier de tests skippe simplement sur les systèmes sans cette installation.

#### Notes de design

La contrainte de plage de ports (1–65535) est appliquée par Python uniquement — le regex du schema permet 1–99999 pour la simplicité. Documenté dans la `description` du schema. Compromis acceptable : le test de parité `Service.from_dict()` garantit que les ports invalides sont rejetés au runtime ; les linters externes obtiennent un warning "good enough" qui attrape les erreurs évidentes (port 0, décimaux, chaînes non numériques).

Le champ `binary` accepte à la fois des noms de binaires (résolus via `$PATH`) et des chemins absolus — le `services.json` bundled utilise les deux formes (e.g. `"in.telnetd"` pour telnet, `"/usr/sbin/postfix"` serait aussi valide).

---

### Hardening — Schéma de plugin réécrit après revue externe

**Fichiers :** `bob/data/schemas/service.schema.json`, `bob/data/schemas/services-list.schema.json`, `bob/data/schemas/plugin-file.schema.json` (nouveau), `bob/data/services.json`, `bob/registry.py`, `tests/test_services_schema.py`

#### Problème

Une revue externe (analyse ChatGPT proposée par l'utilisateur) a relevé 10 points sur le JSON Schema introduit plus tôt dans cette release. Cinq d'entre eux étaient de vraies fuites de contrat qui auraient induit en erreur les packagers de distros et linters externes ; cette section les corrige. Les cinq autres (`ports: [{port,proto}]` typé, objet `port_resolution` remplaçant le mix enum/identifier de `config_key`, `packages: {apt:[],dnf:[]}` multi-PM, union typée pour `binary`, wrapper plugin avec metadata) sont des breaking changes reportés au schéma v2 (planifié pour v0.5.0).

Les cinq corrigés dans cette release :

1. **Promesses des descriptions que le schéma ne valide pas.** La version précédente affirmait « must be unique across all loaded services » et « mirrors `Service.from_dict()` validation » — les deux étaient mensongers. JSON Schema ne peut pas valider l'unicité cross-document, et le schéma ne reflétait qu'un *sous-ensemble* de la validation Python (notamment manquait le check des reserved keywords et la plage stricte 1–65535 pour les ports).
2. **Regex port délibérément lâche** (`^[1-9][0-9]{0,4}/(tcp|udp)$` permettait `99999/tcp`). Un plugin schema-valide pouvait échouer au runtime — cassait le contrat « schema-valid == application-valid ».
3. **Pas de factorisation `$defs`** — patterns string répétés dispersés dans les properties.
4. **Contraintes métier manquantes** — `config_key="auto"` sans `config_files` était valide, un `detection: {}` vide était valide, et un plugin avec `packages: []`, `services: []`, sans `detection` était valide (et indétectable au runtime).
5. **Pas de `schema_version` dans les fichiers plugin** — impossible de gater proprement les futures migrations de schéma.
6. **`$id` pointait vers `github.com/.../blob/main/...`** — URL instable (page HTML, branch-dépendante, pas raw, pas versionnée).

#### Implémentation

**`service.schema.json`** réécrit avec :

- **Bloc `$defs`** factorisant 6 sous-schémas réutilisables : `Identifier`, `PythonIdentifier`, `PackageName`, `SystemdUnit`, `PortProto`, `BinaryRef`, `AbsolutePath`. Chacun porte une description explicite annonçant les changements planifiés en v2 (ports typés, union binary typée).
- **Regex port stricte** `^(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})/(tcp|udp)$` validant exactement 1–65535. Schema-valide égale désormais Python-valide.
- **Description de scope claire** énonçant quels invariants le schéma applique vs quels invariants restent runtime-only (unicité cross-service, exclusion des reserved keywords Python).
- **3 contraintes métier `allOf`** via `if/then` et `anyOf` :
  1. `config_key="fixed"` requiert `ports.minItems: 1` (déjà présent).
  2. `config_key="auto"` requiert `detection.config_files.minItems: 1` (nouveau — sans ça, l'auto-détection n'a rien à parser).
  3. Le service doit être détectable : au moins un parmi `packages`, `services`, ou `detection.{binary|snap}` non-vide (nouveau — empêche de charger des services invisibles).
- **`detection.minProperties: 1`** — blocs detection vides (`detection: {}`) rejetés.
- **`$id` versionné** pointant vers `raw.githubusercontent.com/.../v0.4.0/...` — stable, raw, pin de version.

**`plugin-file.schema.json`** (nouveau) décrit les deux formes acceptées pour `~/.config/bob/services.d/*.json` :

```json
[ { ...service... }, { ... } ]
```

…ou :

```json
{
  "schema_version": 1,
  "services": [ { ...service... } ]
}
```

Le wrapper existe pour que les futures migrations de schéma (v2 ports typés, etc.) puissent être gatées explicitement via `schema_version`. Aujourd'hui seul `schema_version: 1` est accepté ; les champs réservés comme `metadata` / `disabled` sont rejetés aujourd'hui et marqués pour les versions futures.

**`bob/registry.py`** : nouveau helper `_extract_plugin_entries(raw, plugin_name) -> list | None` consomme les deux formes. La constante `_CURRENT_PLUGIN_SCHEMA_VERSION = 1` filtre : les versions supérieures sont rejetées avec un warning « upgrade BOB or downgrade the plugin » donnant un hint clair plutôt qu'un demi-chargement silencieux. Versions inférieures ou non-entières aussi rejetées. Le chemin legacy raw-array est inchangé — rétrocompatibilité préservée.

**`bob/data/services.json`** : 4 services bundled avaient un bloc `detection: {binary: [], snap: [], config_files: []}` qui n'apportait aucun signal. Supprimé entièrement. `postgresql` et `syncthing` avaient `config_key="auto"` sans `config_files` (fonctionnellement équivalent à `fixed`) — migrés à `config_key="fixed"` pour matcher la réalité.

#### Tests

`tests/test_services_schema.py` étendu de 20 à 42 tests (+22) :

- `TestInvalidPluginSamples` mis à jour : `test_port_above_65535_rejected_by_schema` (plus seulement Python), plus tests aux bornes `test_port_65535_accepted` / `test_port_65536_rejected`.
- `TestBusinessConstraints` (nouveau, 7 tests) : `auto` sans `config_files` rejeté, `auto` avec array vide rejeté, `auto` avec paths accepté, service indétectable rejeté, détection binary-only / snap-only acceptée, `detection: {}` vide rejetée.
- `TestPluginFileWrapper` (nouveau, 6 tests) : array legacy accepté, wrapped v1 accepté, `schema_version` manquant rejeté, `services` manquant rejeté, v2 actuellement rejetée, champs extras rejetés.
- `TestRegistryAcceptsBothShapes` (nouveau, 7 tests) : `_extract_plugin_entries` Python accepte les deux formes, rejette unknown / zero / non-int / services manquants, rejette non-array/non-dict.

`jsonschema.RefResolver` utilisé pour la résolution cross-file `$ref` (conservé pour compat avec jsonschema 4.10+ ; le `referencing` Registry moderne de 4.18+ marcherait aussi).

#### Notes de design

- **Schéma v2 reporté délibérément.** Refactoriser `ports: ["22/tcp"]` → `ports: [{port: 22, proto: "tcp"}]` impacte `bob/data/services.json` (32 services), la dataclass `Service`, `_PORT_RE`, chaque check qui itère sur `service.ports`, plus d'importantes réécritures de fixtures de tests. Ce travail appartient à v0.5.0 avec documentation de migration explicite, pas dans cette release.
- **Le wrapper pré-empte le problème v2.** Aujourd'hui `schema_version: 1` est la seule valeur acceptée, mais le champ existe dans le format de fichier dès maintenant. Quand v2 sortira, les fichiers plugin déclarant `schema_version: 2` obtiennent le nouveau validateur ; les plugins v1 continuent de fonctionner via un chemin de compat.
- **Les blocs `detection` vides étaient silencieusement cassés.** Certains services bundled les portaient comme boilerplate ; les retirer fait remonter le vrai signal de détection et évite de futurs copier-coller de config morte.

---

### Hardening passe #2 — descriptions schémas, fixtures tests, compat RefResolver

**Fichiers :** `bob/data/schemas/services-list.schema.json`, `bob/data/schemas/plugin-file.schema.json`, `tests/conftest.py`, `tests/test_json_schema.py`, `tests/test_services_schema.py`

#### Problème

Une seconde passe de revue externe sur les schémas et fichiers de tests fraîchement durcis a fait remonter une plus petite série de problèmes légitimes — aucun structurel cette fois, mais à corriger avant de figer le contrat v0.4.0 :

1. **`services-list.schema.json`** : un tableau vide `[]` était structurellement valide (pas de `minItems`). Un utilisateur créant un fichier plugin et oubliant d'ajouter des entrées obtenait un fichier silencieusement chargé avec zéro service.
2. **`plugin-file.schema.json`** : la description utilisait un wording "schema_version: 1 fallback implicite" qui n'était pas reflété dans le schéma lui-même, et n'expliquait pas *pourquoi* `maximum: 1` est délibéré ou *pourquoi* `additionalProperties: false` rejette les champs mêmes que la description appelle "réservés". Risque : un packager lit la description et pense que le schéma déraille.
3. **`tests/conftest.py`** : `import os` inutilisé (warning pyflakes), et le docstring promettait plus que la fixture n'apporte (set juste les variables d'environnement, n'appelle pas `setlocale()` pour les consommateurs libc/ICU).
4. **`tests/test_json_schema.py`** : injection massive de `MagicMock` dans les fixtures — un attribut renommé dans les types réels passés à `build_json_data` (e.g. `sys_info.fqdn` au lieu de `sys_info.hostname`) passait silencieusement (les mocks inventent les attributs au moment de l'accès). Le validateur de timestamp était un check de substring (`"T" in ts`) qui accepte plein de chaînes non-ISO. Le contrat avait une seule source (les constantes de production `SCHEMA_V1_REQUIRED_KEYS` / `SCHEMA_V1_FULL_KEYS`), donc un edit malheureux des constantes laissait les tests tautologiques.
5. **`tests/test_services_schema.py`** : `RefResolver` est déprécié dans jsonschema ≥ 4.18 (on est sur 4.10 aujourd'hui ; les runners CI sur images plus récentes émettraient `DeprecationWarning`). Les quatre fixtures `validator` par classe dupliquaient le même one-liner. Le check duplicate-id utilisait `ids.count(x)` par élément (O(n²)). Plusieurs `assert errors` ne pinaient pas quel champ l'erreur concerne — une régression ailleurs dans le schéma pouvait masquer un test manquant.

#### Implémentation

**Schémas :**

- `services-list.schema.json` : ajout `"minItems": 1`. Description réécrite pour clarifier qu'il s'agit de la forme canonique de la liste bundled et pour rediriger les utilisateurs vers `plugin-file.schema.json` pour les nouveaux fichiers plugin. Note explicite que l'unicité cross-service de `id` est runtime-only (cohérent avec la clause SCOPE de `service.schema.json`).
- `plugin-file.schema.json` : le titre gagne le suffixe `— schema v1` pour rendre le versioning explicite. Description top-level restructurée en trois sections :
  - **Pourquoi `maximum: 1`** : chaque bump majeur de schéma livre son PROPRE `plugin-file.schema.json` à un NOUVEL `$id`. Un fichier plugin v2 DOIT être validé contre le schéma v2, pas celui-ci.
  - **Pourquoi `additionalProperties: false` rejette les champs "réservés"** : rejeter aujourd'hui empêche les collisions avec le sens que v2/v3 leur donneront.
  - **Fallback runtime `[…] → schema_version: 1`** : explicitement noté comme une convenance d'`_extract_plugin_entries`, PAS une règle du schéma.

**conftest.py** : retiré l'import `os` inutilisé. Docstring énonce explicitement "only sets process environment variables. It does NOT call `setlocale()`" et justifie le triple explicite `LC_ALL`/`LC_MESSAGES`/`LANG` (la précédence POSIX rend les deux derniers redondants quand `LC_ALL` est défini, mais le triple explicite documente l'intention et est robuste contre du code aval qui sonderait directement n'importe quelle variable).

**test_json_schema.py** : réécriture complète des fixtures :
- `MagicMock` remplacés par des instances réelles `SystemInfo`, `PortsSnapshot`, `FirewallStackSnapshot`, `NetworkContextSnapshot`, `CheckResult`. Un attribut renommé dans `bob.json_output.build_json_data` lève désormais `AttributeError` au lieu d'être auto-mocké.
- Le test de timestamp utilise `datetime.fromisoformat(ts)` (ISO 8601 strict) et assert `tzinfo is not None`.
- Source du contrat dupliquée : un set hard-codé `EXPECTED_REQUIRED_KEYS_V1` / `EXPECTED_FULL_KEYS_V1` dans le fichier de test matche contre les constantes de production, donc un edit d'un côté sans l'autre est attrapé (`test_constants_match_expected_set`).
- Nouveau `test_short_mode_strict_set` rejette les clés inattendues qui fuiraient en mode short — les ajouts additifs doivent être explicites (déplacer en full mode ou bumper schema_version).
- Création du engine soulevée dans une fixture pytest (était dupliquée 12+ fois via des appels `_make_engine()`).

**test_services_schema.py :**
- Nouveau helper `_make_resolved_validator(root, extra_schemas)` essaie le path moderne `referencing.Registry` d'abord (jsonschema ≥ 4.18) et retombe sur le `RefResolver` legacy (4.10–4.17). Point de migration unique quand la branche legacy disparaîtra.
- Fixture module-scope `service_validator` remplace quatre duplications par classe ; les fixtures par classe `validator` deviennent des delegates d'une ligne.
- `test_bundled_services_have_unique_ids` passe à `Counter` (O(n)).
- Asserts ciblés via `e.absolute_path` au lieu de matching de substring sur le message, dans les tests les plus informatifs : `test_invalid_port_format`, `test_port_zero_rejected`, `test_port_above_65535_rejected_by_schema`, `test_id_with_spaces_rejected`, `test_empty_binary_string_rejected`. `absolute_path` est stable entre versions de jsonschema ; `e.message` ne l'est pas.

#### Tests

Total **4430/4430** (était 4427 avant cette passe — net +3, tous defense-in-depth) :
- `test_json_schema.py` : 15 → 17 (+`test_short_mode_strict_set`, +`test_constants_match_expected_set`).
- `test_services_schema.py` : 42 → 43 (+`test_services_list_rejects_empty_array` — vérifie le nouveau `minItems: 1`).
- Tous les tests existants passent après le refactor MagicMock-vers-réel — preuve que le code de production accède exactement aux attributs que les dataclasses exposent (aucune divergence cachée).

#### Notes de design

- **Pourquoi deux passes de hardening au lieu d'une release proprement factorisée.** Chaque passe a été déclenchée par une revue externe distincte (ChatGPT) sur les fichiers sélectionnés par l'utilisateur dans son IDE. Les séparer dans le changelog préserve la trace "ce qui a été manqué la première fois", utile pour les postmortems et pour comprendre le resserrement itératif.
- **`assert errors` vs `assert errors[i].absolute_path == [...]`** — gardé `assert errors` sur les cas triviaux (e.g. `test_unknown_field_rejected`, `test_fixed_without_ports_rejected`) où le mode de défaillance est "n'importe quelle erreur". Resserré uniquement sur les tests où plusieurs violations distinctes pourraient se masquer mutuellement.
- **Defense in depth via liste de clés dupliquée.** Le set `EXPECTED_REQUIRED_KEYS_V1` dans le fichier de test est intentionnellement une copie de `SCHEMA_V1_REQUIRED_KEYS`. Le test `test_constants_match_expected_set` est le filet de sécurité : un edit non-intentionnel de la constante de production fait passer le test au rouge, forçant l'éditeur à acquitter le changement de contrat.

---

### Bonus UX — Suffixe `= N` redondant sur score inchangé supprimé

**Fichiers :** `bob/display.py`, `tests/test_min_level.py`

#### Problème

Le test terrain sur so6desktop a montré :

```
║  Score de sécurité : 8/10  = 8                                               ║
```

Le `= 8` était un vestige d'un fix v0.3.0 ("score delta orphan arrow: stable score shows = N instead of bare →") — l'intention originelle était d'éviter une `→` orpheline quand le score était inchangé, mais la forme `= N` finit redondante : le score `8/10` est déjà deux caractères avant sur la même ligne.

#### Implémentation

Dans `bob/display.py:print_audit_summary()`, la branche `delta == 0` est supprimée entièrement :

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

`tests/test_min_level.py:TestScoreTrend::test_stable_shows_equal` renommé `test_stable_shows_no_annotation` et inversé : assert désormais qu'aucune flèche `↑`/`↓` n'apparaît et que la valeur est exactement `"7/10"` (sans suffixe).

---

### Récap tests — 4430/4430 (+82)

| Fichier de test | Classe | Nouveaux | Existants |
|---|---|----:|----:|
| `tests/test_exit_codes.py` | (existants) | 0 | 18 |
| `tests/test_i18n.py` | `TestDetectSystemLang` | +12 | — |
| `tests/test_cli.py` | `TestParse::test_*_locale` | +4 | — |
| `tests/test_json_schema.py` (nouveau) | 4 classes | +17 | — |
| `tests/test_explain.py` | `TestExplainKeyAliases`, `TestExplainKeyFreezePolicy` | +6 | — |
| `tests/test_services_schema.py` (nouveau) | 9 classes | +43 | — |
| `tests/test_min_level.py` | `TestScoreTrend::test_stable_shows_no_annotation` | renommé | — |
| `tests/conftest.py` (nouveau) | fixture autouse force `LANG=C` | — | — |

Notes sur la trajectoire de ces décomptes pendant le développement de v0.4.0 :
- `test_services_schema.py` : 20 (initial) → 42 (passe de hardening post-revue #1) → 43 (passe #2 a ajouté `test_services_list_rejects_empty_array` pour le nouveau `minItems: 1`).
- `test_json_schema.py` : 15 (initial) → 17 (passe #2 a ajouté `test_short_mode_strict_set` et `test_constants_match_expected_set` comme defense-in-depth contre les dérives silencieuses du contrat).

### Validation terrain

Audit bout en bout sur so6desktop (Linux Mint 22.3) confirme :
- Bannière v0.4.0 correctement affichée
- Locale auto-détectée comme français via `$LANG=fr_FR.UTF-8`
- Toutes les sections rendues correctement ; journalisation UFW affichée (UFW actif), link-local IPv6 correctement classés, plugins/profils chargés depuis `/home/so6/.config/bob/`
- Score 8/10, delta tracé depuis l'audit précédent, ligne "Score inchangé" affichée sans suffixe redondant `= 8`
- 4405 tests verts, pyflakes propre (un seul `# noqa: F401` intentionnel)

---

## [v0.3.6] — 09-05-2026

Passe de code review suite à un audit approfondi du code. Aucune nouvelle fonctionnalité, aucun changement de comportement, aucun nouveau test — uniquement des corrections de bugs, du nettoyage d'hygiène et des améliorations de cohérence. Huit correctifs liés couvrant la résolution de chemin sudo-aware, la couverture des plages privées IPv6, la sémantique du check SSH, le rendu de section UFW, la compatibilité legacy cron, le placement des sub-checks, les imports morts et les clés de locales mortes. 4348/4348 tests.

---

### Correctif — `Path.home()` retourne `/root` sous sudo (+ helper chown pour les fichiers écrits sous sudo)

**Fichiers :** `bob/config.py`, `bob/recurrence.py`, `bob/history.py`, `bob/registry.py`, `bob/compare.py`, `bob/profiles.py`, `bob/plugin_checks.py`, `bob/ignore.py`, `bob/sysinfo.py`

#### Problème

Sept modules calculaient des constantes de chemin au niveau du module avec `Path.home()` :

```python
_DEFAULT_CONFIG_DIR = Path.home() / ".config" / "bob"        # config.py
_PLUGIN_DIR        = Path.home() / ".config" / "bob" / "services.d"  # registry.py
_USER_PROFILES_DIR = Path.home() / ".config" / "bob" / "profiles"    # profiles.py
# ... et 4 autres
```

`Path.home()` consulte `$HOME`. Sous `sudo`, `$HOME` vaut typiquement `/root` (préservé à travers la frontière sudo sur la plupart des distros). Résultat : BOB cherchait les profils utilisateur dans `/root/.config/bob/profiles/`, les plugins dans `/root/.config/bob/services.d/`, la baseline dans `/root/.config/bob/last_baseline.json`, etc. — sans jamais lire la configuration de l'utilisateur invoquant.

Un helper correct existait déjà : `bob.sysinfo.get_user_home()` honore `SUDO_USER` et retombe sur `Path.home()` :

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

…mais il n'était utilisé qu'à deux endroits (`sysinfo.py:91`, `manage_logs.py:155`).

#### Implémentation

Les sept modules importent `get_user_home` depuis `bob.sysinfo` et remplacent `Path.home()` par `get_user_home()` dans les constantes concernées. La résolution se fait toujours à l'import (préserve la surface d'API existante — beaucoup d'appelants référencent ces constantes directement), mais pointe désormais correctement sur le home de l'utilisateur invoquant. `bob/ignore.py` avait sa propre logique `SUDO_USER` dupliquée — remplacée par un appel au helper partagé.

#### Correctif compagnon — helper `chown_to_sudo_user(path)`

Pointer la config vers `~/.config/bob/` sous sudo n'est que la moitié du correctif : les écritures se font en root, donc chaque fichier nouvellement créé finit propriété de root. Lors d'une session non-sudo ultérieure, l'utilisateur ne peut plus lire ni éditer sa propre config.

Un nouveau helper `bob.sysinfo.chown_to_sudo_user(path)` chown un chemin vers l'uid/gid de `SUDO_USER`. No-op quand :
- `SUDO_USER` n'est pas défini (login root réel ou utilisateur normal)
- `SUDO_USER` échoue la regex de validation
- L'appel chown lui-même échoue (best-effort — le helper avale `OSError`)

Appliqué à chaque site d'écriture de config utilisateur :
- `bob/config.py` — après `mkdir(parents=True, mode=0o700)` et après chaque `replace` atomique (UserConfig + EmailStore)
- `bob/compare.py` — après `mkdir(parents=True)` et après `tmp.replace(dest)` pour la baseline
- `bob/recurrence.py` — après `mkdir(parents=True)` et après `tmp.replace(dest)`
- `bob/history.py` — après `mkdir(parents=True)`, après le premier `open("a")` si le fichier n'existait pas, et après chaque rotation `os.replace`
- `bob/ignore.py` — après `mkdir(parents=True)` et après `write_text`

#### Correctif compagnon — gardes `PermissionError` sur les lectures de plugins

Les installations existantes peuvent avoir un répertoire `~/.config/bob/services.d/` ou `checks.d/` créé par root depuis un run sudo antérieur au fix. Après le fix, la session utilisateur tente de lire ces répertoires et obtient `PermissionError`. Trois sites de lecture obtiennent une garde pour que l'audit retombe gracieusement sur « aucun plugin chargé » au lieu de crasher :

- `bob/registry.py:_load_plugins` — `_PLUGIN_DIR.is_dir()` et `_PLUGIN_DIR.glob()` enveloppés dans try/except PermissionError
- `bob/plugin_checks.py:load_plugin_checks` — même pattern sur `_PLUGIN_CHECKS_DIR`
- `bob/profiles.py:_resolve_path` — `candidate.is_file()` enveloppé par dossier, retombe sur le suivant

#### Notes de design

- Le helper valide `SUDO_USER` contre une regex stricte avant la lecture via `pwd.getpwnam` — défense contre l'injection de variable d'environnement.
- Pas de risque d'import circulaire : `bob.sysinfo` n'importe que la stdlib au niveau module (`bob.report` et `bob.output` sont importés en lazy dans `collect_system_info()`).
- Le fallback `Path.home()` à l'intérieur de `get_user_home()` préserve le comportement quand BOB est invoqué hors contexte sudo.
- `chown_to_sudo_user` est best-effort — les échecs sont loggés en debug et ne se propagent jamais. Le fallback (fichier propriété de root) est le comportement antérieur au fix, donc le mode de défaillance équivaut au comportement précédent.

#### Migration pour utilisateurs existants

Les utilisateurs ayant lancé une version pré-fix de BOB sous sudo peuvent avoir un `~/.config/bob/` propriété de root. Pour restaurer l'accès :

```
sudo chown -R "$USER:$USER" ~/.config/bob/
```

Les futurs runs sudo chowneront automatiquement les nouveaux fichiers via le helper.

---

### Correctif — `AllowTcpForwarding local` signalé comme avertissement

**Fichiers :** `bob/checks/ssh.py:553`

#### Problème

Le check SSH n'acceptait que `AllowTcpForwarding no` comme sûr :

```python
atf = cfg.get("allowtcpforwarding", "yes").lower()
if atf not in ("no",):
    result.warn(message=_t("ssh.allow_tcp_forwarding"), ...)
    result.add_deduction(reason=..., points=1, ...)
```

OpenSSH supporte une troisième valeur — `local` — qui ne permet le port forwarding qu'entre processus du serveur SSH lui-même, pas entre le client et des hôtes arbitraires. Plus restrictif que `yes`, il est explicitement recommandé dans le texte de remédiation BOB (champ `how` dans `locales/fr.json`) :

> « Si certains utilisateurs ont besoin du transfert de port, utilisez : `AllowTcpForwarding local` »

Définir `local` était donc à la fois *plus sécurisé que la valeur par défaut* et *contredit par le scoring BOB lui-même* : ça déclenchait l'avertissement et déduisait 1 point.

#### Implémentation

```python
if atf not in ("no", "local"):
```

`no` et `local` sont désormais tous deux acceptés. `yes` (défaut) et `all` continuent de déclencher l'avertissement.

---

### Correctif — En-tête journalisation UFW affiché quand UFW inactif

**Fichiers :** `bob/runner.py:233`

#### Problème

```python
# ---- CHECK 40 — UFW logging level ----
if not config.quiet:
    print_section(t("sections.ufw_logging"))
report.write_section(t("sections.ufw_logging"))

ufw_logging_result = check_ufw_logging(fw_status, t=t)
engine.apply(ufw_logging_result)
display_result(ufw_logging_result, report, ...)
```

`check_ufw_logging()` retourne un `CheckResult` vide quand UFW est inactif (lignes 407–408 de `firewall.py`), car le cas est déjà couvert par `check_firewall`. Mais l'en-tête de section est imprimé inconditionnellement, produisant ceci à l'écran et dans le rapport quand UFW est désactivé :

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  JOURNALISATION UFW                                                          │
└──────────────────────────────────────────────────────────────────────────────┘

```

…suivi immédiatement de la section suivante. Bruit visuel.

#### Implémentation

Tout le bloc encapsulé dans `if fw_status.active:`. Quand UFW est inactif, l'en-tête n'est pas imprimé et le résultat (vide) n'est pas affiché.

---

### Correctif — ULA et link-local IPv6 traités comme externes

**Fichiers :** `bob/checks/network_context.py:297`

#### Problème

`_is_private_or_loopback()` reconnaissait :
- Loopback IPv4 (`127.0.0.0/8`)
- RFC-1918 IPv4 (`10/8`, `172.16/12`, `192.168/16`)
- Loopback IPv6 (`::1`)

Mais omettait deux plages IPv6 importantes :
- `fc00::/7` — Unique Local Addresses (RFC-4193, équivalent IPv6 de RFC-1918)
- `fe80::/10` — adresses link-local (utilisées typiquement pour la découverte de voisins, pas pour la connectivité externe)

Une connexion entre deux adresses `fe80::` sur le même lien, ou deux `fc00::` sur un réseau privé, était classée comme *externe* — entraînant des avertissements faux positifs et une mauvaise catégorisation de l'exposition.

Le même module utilisait précédemment une vérification par préfixe de chaîne maison. À l'inverse, `bob/checks/auth_log.py` utilisait déjà `ipaddress.ip_network()` avec la liste correcte :

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

#### Implémentation

`network_context.py` utilise désormais le même tuple `_PRIVATE_NETWORKS` et la même vérification basée sur `ipaddress.ip_address()` :

```python
def _is_private_or_loopback(addr: str) -> bool:
    bare = addr.split("%", 1)[0]   # strip IPv6 zone-id (ex : "fe80::1%eth0")
    try:
        ip = ipaddress.ip_address(bare)
    except ValueError:
        return False
    return any(ip in net for net in _PRIVATE_NETWORKS)
```

Aligné avec `auth_log.py`. Le strip du `%` gère les zone identifiers dans les adresses link-local, que `ipaddress.ip_address()` n'accepte pas directement.

---

### Correctif — Regex `NOTIFY_EMAIL` legacy silencieusement ignoré

**Fichiers :** `bob/cron.py:820`, `bob/locales/en.json`, `bob/locales/fr.json`

#### Problème

`edit_cron_email()` patche la ligne `NOTIFY_EMAILS=` dans les scripts cron installés par BOB :

```python
text = re.sub(
    r"^NOTIFY_EMAILS=.*$",
    lambda _: f"NOTIFY_EMAILS={shlex.quote(new_email)}",
    text, flags=re.MULTILINE,
)
```

Les scripts pré-v0.x utilisaient le singulier `NOTIFY_EMAIL=` (sans S). Les utilisateurs ayant installé des crons avec une version précoce voyaient la fonction signaler le succès — mais aucune ligne ne matchait, donc rien ne changeait. Échec silencieux.

#### Implémentation

```python
text, n = re.subn(
    r"^NOTIFY_EMAILS?=.*$",   # match les deux formes
    lambda _: f"NOTIFY_EMAILS={shlex.quote(new_email)}",   # toujours réécrire au format actuel
    text, flags=re.MULTILINE,
)
if n == 0:
    print(f"  ⚠ {t('manage_cron.email_not_found_in_script')}")
```

`subn()` retourne le nombre de substitutions. Quand zéro, un avertissement est imprimé via une nouvelle clé locale :
- EN : `"No NOTIFY_EMAIL line found in the script — email not patched (script may be outdated)."`
- FR : `"Aucune ligne NOTIFY_EMAIL trouvée dans le script — email non mis à jour (script obsolète ?)."`

Les anciens scripts sont migrés vers la nouvelle clé (`NOTIFY_EMAILS=`) à la prochaine édition.

---

### Refactoring — `_check_weak_algo` déplacé dans la section sub-check

**Fichiers :** `bob/checks/ssh.py`

#### Problème

`bob/checks/ssh.py` est organisé par en-têtes de section :
- `# Sub-check functions` — `_check_host_keys`, `_check_sshd_config`, …
- `# Parsing helpers` — `_parse_config_file`, `_collect_private_keys`, …

`_check_weak_algo` (introduit en v0.3.5 pour dédupliquer la logique weak-cipher / weak-MAC / weak-kex) était placé sous `# Parsing helpers`. Mais il accepte un `CheckResult` et écrit des findings via `result.warn()` / `result.add_deduction()` — par tout signal pertinent c'est un sub-check, pas un helper de parsing.

#### Implémentation

Déplacé immédiatement après `_check_sshd_config` (son seul appelant), avant `_check_ssh_dir`. La section `# Parsing helpers` ne contient désormais que de vraies fonctions de parsing.

---

### Nettoyage — 22 imports inutilisés supprimés

**Fichiers :** `bob/__main__.py`, `bob/cron_ui.py`, `bob/output.py`, `bob/explain.py`, `bob/exposure.py`, `bob/registry.py`, `bob/report.py`, `bob/cron.py`, `bob/watch.py`, `bob/checks/iptables_nftables.py`, `bob/checks/firmware.py`, `bob/checks/ports.py`, `bob/checks/log_rotation.py`, `bob/checks/auth_log.py`, `bob/checks/logs.py`, `bob/checks/virtualization.py`, `bob/checks/smtp.py`, `bob/checks/disk.py`, `bob/checks/auditd.py`, `bob/checks/ddns.py`, `bob/checks/hardening.py`

#### Problème

`pyflakes bob/` reportait 22 imports inutilisés — vestiges de refactorings successifs (v0.3.0 → v0.3.5) :
- `dataclasses.field` dans 6 modules sans appel `field()` restant
- `typing.{Optional, List, Tuple, Dict}` dans 4 modules
- `pathlib.Path` dans 2 modules
- `bob.scoring.{ScoreEngine, Finding, FindingLevel}` dans `report.py` (bloc TYPE_CHECKING)
- `shutil` dans `output.py` et `cron.py` (re-import local)
- `bob.checks._run._C_LOCALE_ENV` dans `iptables_nftables.py`
- `bob.cron.prompt_emails`, `pathlib.Path` dans `cron_ui.py`
- `bob.config.UserConfig` dans `watch.py`
- `bob.webhook.WebhookError` dans `__main__.py` (remplacé par catch `Exception`)
- `bob.runner._ALL_SECTIONS` re-importé localement dans `__main__.py:91`

Plus trois problèmes structurels :
1. `bob/checks/logs.py:633` — paramètre `field` shadowait `dataclasses.field` de la ligne 25, déclenchant à la fois l'avertissement d'import inutilisé et un avertissement de redéfinition. Renommé en `field_name`.
2. `bob/checks/hardening.py:114` — variable locale `found_issue = False` assignée à 8 endroits (`found_issue = True`) mais jamais lue. Les 8 affectations et l'initialiseur supprimés.
3. `bob/output.py:351` — `bar = "─" * inner` calculé mais inutilisé ; `bob/cron_ui.py:244` — `_SCHEDULE_DAILY` dépaqueté d'un tuple mais jamais référencé (remplacé par `_`).

#### Implémentation

Chaque import a été tracé (grep du symbole dans le fichier) avant suppression. Là où un bloc TYPE_CHECKING devenait vide (`bob/report.py`), tout le bloc, y compris `if TYPE_CHECKING:`, a été supprimé.

L'unique avertissement pyflakes restant est `bob/__main__.py:24` — un re-export `# noqa: F401` intentionnel d'`AuditConfig` pour les appelants qui font `from bob.__main__ import AuditConfig`.

---

### Nettoyage — 47 clés de locales mortes supprimées

**Fichiers :** `bob/locales/en.json`, `bob/locales/fr.json`

#### Problème

Les deux fichiers de locales avaient grossi à 2049 lignes / 1435 clés chacun. Un audit de chaque clé contre les sites d'appel `t()` et `_t()` réels — incluant les patterns dynamiques comme `t(f"services.exposure.{name}")` et les références indirectes via les paramètres `t_key` dans les helpers — a révélé 47 clés vraiment orphelines.

#### Implémentation

Supprimées (groupées par parent) :

| Parent | Clés supprimées | Raison |
|--------|-----|--------|
| `cli.help_*` | 14 | Ancien système d'aide remplacé par `print_help()` codé en dur dans `cli.py:555` |
| `errors.*` | 3 | Objet entier : `must_be_root`, `unknown_option`, `ufw_not_found` (tous remplacés par exceptions) |
| `geo.*` | 1 | Objet entier : `local_network` |
| `profile.*` | 3 | Objet entier : `active`, `not_found`, `section_skipped` |
| `report.*` | 3 | `title`, `next_steps`, `system_info` |
| `cli.help`, `errors`, `geo`, `profile` | (objets) | Objets entiers vides supprimés |
| Diverses feuilles | 20 | `prerequisites.{ss_available, ss_missing}`, `network_context.{interfaces_found, no_connections, connections_found}`, `ports.ephemeral_ignored`, `logs.{geo_unavailable, local_network}`, `ddns.{ports_title, high_warn}`, `summary.block_normal`, `fixes.done`, `risk_context.level`, `log_dir.{default_hint, use}`, `install_cron.{prompt_email, done}`, `manage_cron.edit_schedule`, `config.{port_prompt, port_saved}`, `deduction.local_dominance`, `status.{ok, info}` |

Préservées malgré l'absence d'usage :
- `_meta.lang`, `_meta.version` — clés de métadonnées réservées

Les deux fichiers restent synchrones (1388 clés chacun, parité EN/FR vérifiée).

#### Notes de design

Audit effectué en extrayant chaque clé aplatie, puis en cherchant avec grep les usages statiques (`t("key.subkey")`) et dynamiques (`f"key.{var}"`). Approche conservatrice : toute clé avec ne serait-ce qu'une possibilité distante de référence dynamique a été conservée.

Lignes économisées : 2049 → 1994 (−55 par fichier, −110 au total).

---

### Tests

4348/4348 — aucun changement de tests. Tous les correctifs sont couverts par les tests existants ; aucune régression introduite. Pyflakes est propre (un seul `# noqa: F401` intentionnel restant pour le re-export `AuditConfig`).

Validé bout en bout sur so6desktop (Linux Mint 22.3) — audit complet avec score 8/10 (Pare-feu & Services 10/10, SSH 7/10, Durcissement 6/10) et toutes les sections correctement rendues. La section journalisation UFW apparaît (UFW actif) ; la section cohérence IPv6 indique « link-local uniquement » ; les profils, plugins et baselines sont correctement chargés depuis `/home/so6/.config/bob/`.

---

## [v0.3.5] — 08-05-2026

Refactoring interne pur et correctif des locales — aucune nouvelle fonctionnalité, aucun changement de comportement, aucun nouveau test. Deux tâches indépendantes plus un correctif de contenu : les blocs de sections répétitifs dans `runner.py` remplacés par une closure `_sec` (−295 lignes), la logique de vérification d'algorithmes faibles triplicata dans `ssh.py` remplacée par un helper `_check_weak_algo` (−26 lignes), et quatre clés de traduction référençant encore l'ancien nom d'outil `UFW-AUDIT` corrigées en `BOB`. 4348/4348 tests.

---

### Refactoring — closure `_sec` dans `runner.py`

**Fichiers :** `bob/runner.py` (951 L → 656 L, −295 lignes)

#### Problème

`run_checks()` contenait 29 blocs quasi-identiques de 7 à 13 lignes, un par section d'audit :

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

951 lignes au total. La répétition rendait impossible l'ajout d'un traitement transversal (par ex. un hook entre chaque section) sans modifier 29 sites.

#### Implémentation

**`_pname` pré-calculé une fois** après `_pr` :

```python
_pname = profile.name if profile is not None else "server"
```

Utilisé par les 7 sections qui acceptent `profile_name=` : `kernel_modules`, `mac_policy`, `updates`, `memory`, `backup`, `auditd`, `secure_boot`. `check_firmware` n'accepte pas `profile_name` — intentionnellement exclu.

**Closure `_sec`** définie immédiatement après :

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

29 blocs standards remplacés par des appels en une ligne :

```python
_sec("kernel_modules", km_snapshot,  check_kernel_modules,  profile_name=_pname)
_sec("ssh",           ssh_snapshot,  check_ssh,             ssh_exposed=_ssh_exposed)
_sec("ipv6",          ipv6_snapshot, check_ipv6,            ufw_active=fw_status.active)
# …et 26 autres
```

Sections conservées en manuel (non converties) : firewall, rules, ufw_logging, groupes réseau/affichage, samba, docker_audit, desktop_apps, iptables_nft (toutes comportent une logique conditionnelle autour de `.installed`, `.detected`, ou `not fw_status.active` qui ne peut pas être abstraite dans la closure sans ajouter de complexité).

**`apply_profile` maintenant appliqué à `auth_log`** — omis par inadvertance auparavant. Sans effet en pratique (aucun profil ne définit d'overrides spécifiques à auth_log), mais désormais cohérent avec toutes les autres sections.

#### Décisions de conception

- **Closure plutôt qu'helper module** : `_sec` capture `config`, `profile`, `engine`, `report`, `t`, `_pr` depuis la portée englobante. Un helper module nécessiterait de passer les six en paramètre à chaque appel — plus verbeux, aucun avantage.
- **`check_fn(snapshot, t=t, **check_kwargs)` et non `check_fn(snapshot, **{"t": t, **check_kwargs})`** : `t` est toujours positionnel-mot-clé ; la forme keyword-splat est correcte et explicite.

---

### Refactoring — helper `_check_weak_algo` dans `ssh.py`

**Fichiers :** `bob/checks/ssh.py` (1406 L → 1380 L, −26 lignes)

#### Problème

`_check_sshd_config()` contenait trois blocs identiques de 16 lignes pour vérifier les algorithmes Ciphers, MACs et KexAlgorithms faibles :

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

Répété pour `macs` et `kexalgorithms` avec seulement les noms de variables, ensembles, clés de traduction et valeurs de points qui diffèrent.

#### Implémentation

Helper module `_check_weak_algo` extrait avant `_parse_config_file` :

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

Trois sites d'appel dans `_check_sshd_config` :

```python
found_issue |= _check_weak_algo(cfg, result, _t, "ciphers",       _WEAK_CIPHERS, "ssh.weak_ciphers", "ciphers", 2)
found_issue |= _check_weak_algo(cfg, result, _t, "macs",          _WEAK_MACS,    "ssh.weak_macs",    "macs",    1)
found_issue |= _check_weak_algo(cfg, result, _t, "kexalgorithms", _WEAK_KEX,     "ssh.weak_kex",     "kex",     1)
```

#### Décision de conception

**Module plutôt que closure** : contrairement à `_sec`, ce helper reçoit toutes ses entrées en paramètres et ne dépend pas d'une portée extérieure. Une fonction module la rend indépendamment testable et visible pour d'éventuels futurs appelants.

---

### Correctif — chaînes de locale `UFW-AUDIT` → `BOB`

**Fichiers :** `bob/locales/en.json`, `bob/locales/fr.json`

#### Problème

Quatre clés de traduction dans les deux fichiers de locale référençaient encore l'ancien nom d'outil `UFW-AUDIT` au lieu de `BOB` :

| Clé | Avant (FR) | Après (FR) |
|-----|------------|------------|
| `install_cron.title` | `INSTALLATION CRON UFW-AUDIT` | `INSTALLATION CRON BOB` |
| `manage_cron.title` | `GESTION DES CRONS UFW-AUDIT` | `GESTION DES CRONS BOB` |
| `manage_cron.no_crons` | `Aucun cron UFW-AUDIT installé.` | `Aucun cron BOB installé.` |
| `report.title` | `RAPPORT UFW-AUDIT` | `RAPPORT BOB` |

Ces chaînes apparaissaient dans les écrans de configuration et gestion des crons, ainsi que dans le titre de section du rapport. Les autres références `UFW` dans les fichiers de locale sont légitimes — elles désignent l'outil pare-feu UFW lui-même, pas l'ancien nom d'outil.

#### Implémentation

Remplacement de chaîne simple dans `en.json` et `fr.json`. Aucun changement de logique.

---

## [v0.3.4] — 08-05-2026

Version hotfix — aucune nouvelle fonctionnalité, aucun changement de comportement, aucun nouveau test. Corrige un `NameError` fatal introduit en v0.3.2 : `user_config` n'était pas passé à `run_checks()`. 4348/4348 tests.

---

### Fix — `user_config` non passé à `run_checks()`

**Fichiers :** `bob/runner.py`, `bob/__main__.py`

#### Problème

La v0.3.2 a ajouté la whitelist SUID utilisateur. `run_checks()` a été étendue avec un appel à `user_config.get_suid_whitelist()` dans le bloc de vérification SUID (CHECK 37), mais `user_config` n'a jamais été ajouté comme paramètre de `run_checks()`. Le site d'appel dans `__main__.py` ne le passait donc pas.

Résultat : chaque audit atteignant le CHECK 37 (audit SUID/SGID) plantait avec :

```
NameError: name 'user_config' is not defined
```

Régression fatale sur toutes les machines — l'audit atteint toujours le CHECK 37.

#### Implémentation

`runner.py` — paramètre ajouté et accès protégé :

```python
def run_checks(
    ...
    user_config: UserConfig | None = None,   # ajouté
) -> ChecksResult:
    ...
    suid_snapshot = SuidSnapshot.from_system(
        user_whitelist=user_config.get_suid_whitelist() if user_config is not None else []
    )
```

`__main__.py` — site d'appel mis à jour pour passer `user_config`.

#### Validation

Testé sur 5 VMs (Linux Mint 22.3, Debian 13, Ubuntu 26.04, Kali, so6desktop) — audit complet sans erreur sur toutes.

---

## [v0.3.3] — 07-05-2026

Refactoring interne pur — aucune nouvelle fonctionnalité, aucun changement de comportement. Quatre tâches de nettoyage issues d'une passe de code review : découpage de `cron.py`, retour pur de `compute_domain_scores()`, API publique de `domain_scores`, helpers curses dans `cron_ui.py`. 4348/4348 tests (+1).

---

### Refactoring — découpage de `cron.py`

**Fichiers :** `bob/cron.py`, `bob/cron_ui.py` (nouveau)

#### Problème

`bob/cron.py` avait atteint 2 181 lignes en mélangeant des préoccupations hétérogènes : types de données, parsers, logique cron, flux interactifs en texte brut, et un TUI curses complet. Le code curses importait `curses` au niveau module, ce qui déclenchait une `_curses.error` à l'import dans tout test sans TTY. Les flux d'installation et de gestion contenaient chacun un bloc de génération de script bash de 40 lignes — logique identique copié-collée.

#### Implémentation

**Découpage**

`bob/cron.py` conserve tous les types de données, parsers, logique domaine, et flux interactifs en texte brut. `bob/cron_ui.py` (nouveau, 955L) contient tout le code TUI curses. Les dispatchers `run_install_cron()` / `run_manage_cron()` utilisent un pattern d'import paresseux :

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

Le `import curses as _c` à l'intérieur des fonctions de `cron_ui.py` est intentionnel : le déplacer au niveau module casserait les imports dans les tests sans terminal.

**`build_script_content(notify_email, log_dir) -> str`**

Fonction pure extraite des deux flux d'installation dans `cron.py`, éliminant une duplication de 40 lignes. Retourne la chaîne complète du script bash. Appelée depuis `_run_install_cron_plain()` et `_run_install_cron_curses()`.

---

### Refactoring — retour pur de `compute_domain_scores()`

**Fichiers :** `bob/scoring.py`, `bob/domain_scores.py`, `bob/breakdown.py`

#### Problème

`compute_domain_scores()` communiquait quelles déductions étaient cappées en posant `deduction.was_capped = True` comme effet de bord sur des objets `Deduction` live. Non-idempotent (corrigé en v0.3.2 par un reset en début de fonction), mais la cause racine restait : une fonction qui mutait ses entrées pour transmettre une information aux appelants. `breakdown.py` itérait `engine.breakdown` et vérifiait `was_capped` pour annoter le tableau de breakdown.

#### Implémentation

Champ `Deduction.was_capped: bool` supprimé du dataclass.

`compute_domain_scores()` retourne désormais `tuple[dict[str, dict], frozenset[int]]` — le second élément est l'ensemble des indices dans `engine.breakdown` réduits par un cap de domaine. La fonction calcule ce frozenset purement par comparaison `effective < raw` sans toucher aucun objet.

`ScoreEngine.set_domain_scores()` reçoit un paramètre `capped_indices: frozenset[int]`, stocké en `_capped_indices`. Nouvelle propriété `capped_indices` pour l'exposer. `breakdown.py` lit `engine.capped_indices` au lieu d'inspecter `was_capped` sur chaque déduction.

#### Décisions de conception

- **`frozenset[int]` et non `set[Deduction]`** : les indices sont stables dans un appel `compute_domain_scores()` ; le frozenset est immuable et sûr en cache. Des références à des objets `Deduction` créeraient une dépendance implicite sur l'identité des objets.
- **Retour du frozenset plutôt que stockage interne** : la fonction n'a plus d'effets de bord, ce qui la rend trivialement testable par assertion directe sur la valeur de retour.

---

### Refactoring — API publique de `domain_scores.py`

**Fichiers :** `bob/domain_scores.py`, `bob/breakdown.py`, `bob/explain.py`, `tests/test_domain_scores.py`

#### Problème

Trois noms au niveau module — `_LABELS`, `_TOOL_CAPS`, `_key_to_domain` — étaient effectivement publics : utilisés directement par `breakdown.py` et `explain.py`. Le tiret bas suggérait qu'ils étaient des détails internes privés, mais des appelants externes en dépendaient. Signal trompeur : tout appelant voyant `from bob.domain_scores import _LABELS` savait qu'il importait un nom privé.

#### Implémentation

Renommage simple : `_LABELS → LABELS`, `_TOOL_CAPS → TOOL_CAPS`, `_key_to_domain → key_to_domain`. Tous les appelants mis à jour (`breakdown.py`, `explain.py`, `tests/test_domain_scores.py`). Aucune logique modifiée.

---

### Refactoring — helpers curses dans `cron_ui.py`

**Fichiers :** `bob/cron_ui.py`

#### Problème

`cron_ui.py` présentait trois catégories de duplication structurelle :

1. **Génération de script** : script bash de 40 lignes dupliqué entre les flux d'installation texte brut et curses (traité ci-dessus par `build_script_content`).
2. **`addstr` sécurisé** : chaque écriture à l'écran était enveloppée dans `try: stdscr.addstr(...) except _c.error: pass` — 30+ blocs identiques de 3 lignes.
3. **Lecture de touche** : chaque boucle interactive contenait `try: ch = stdscr.get_wch() / except _c.error: continue` suivi d'une normalisation `isinstance(ch, int)` / `isinstance(ch, str)` — 9 duplications séparées.
4. **Indices magiques de planning** : `if choice == 2 / 3 / 4` disséminé dans `_curses_schedule_wizard` sans explication de ce que signifient 2, 3, 4.
5. **Stub `_FakeEntry`** : une bare `class _FakeEntry: pass` avec attribut `entry.name = raw_name` posé au runtime — non typé, non documenté.

#### Implémentation

**`_WizardEntry(name, hour=3, minute=0)` NamedTuple**

Remplace `_FakeEntry`. Créé à `STEP_SCHEDULE` avec `_WizardEntry(raw_name)`, passé à `_curses_schedule_wizard`. Typé, documenté, immuable.

**`_draw(stdscr, row, col, text, attr=0) -> None`**

```python
def _draw(stdscr, row: int, col: int, text: str, attr: int = 0) -> None:
    try:
        stdscr.addstr(row, col, text, attr)
    except Exception:
        pass
```

Absorbe les 30+ blocs `try/except curses.error`. Utilise `except Exception` (et non `except _c.error`) car `curses` n'est pas importé au niveau module — `_c` est un alias local à l'intérieur de chaque fonction.

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

Retourne -1 en cas d'erreur ou d'entrée non reconnue. Les appelants qui faisaient précédemment `continue` sur erreur laissent désormais tomber toutes les branches `if/elif` sans match — comportement de redémarrage de boucle identique. Le seul cas limite où `-1` pourrait être matché par erreur (`_run_manage_cron_curses` confirm-delete) a été audité : le guard `if key in (ord("y"), ord("Y"))` signifie que `-1` annule simplement, ce qui est le comportement "toute touche : annuler" documenté.

**`_SCHEDULE_DAILY/WEEKDAYS/MONTHDAYS/CUSTOM = 1, 2, 3, 4`**

Constantes nommées remplaçant les indices magiques dans `_curses_schedule_wizard`.

#### Résultat net

1 104L → 955L (−149 lignes, −13 %).

---

### Tests

4 348 / 4 348 (+1 par rapport à v0.3.2).

`TestWasCapped` (vérifiait le flag `was_capped`) remplacé par `TestCappedIndices` (7 tests) couvrant le contrat de retour frozenset de `compute_domain_scores()` : ensemble vide quand aucun cap n'est déclenché, indices corrects quand les caps s'appliquent, immuabilité du frozenset retourné.

---

## [v0.3.2] — 06-05-2026

Liste blanche SUID configurable par l'utilisateur : les patterns déclarés dans `~/.config/bob/config.conf` suppriment les binaires légitimes du warning "SUID inattendu". Plus 14 corrections issues d'une passe de code review (i18n, mode quiet, idempotence moteur, code mort). 4347/4347 tests (+19).

---

### Fonctionnalité — `suid_whitelist` dans `config.conf`

**Fichiers :** `bob/config.py`, `bob/checks/suid_audit.py`, `bob/runner.py`, locales

#### Problème

Sur Kali Linux et autres distributions orientées sécurité, des outils légitimes sont livrés avec le bit SUID positionné (Kismet livre 15+ helpers de capture `kismet_cap_*`, tous root-owned SUID). Ces binaires apparaissent comme "inattendus" dans le rapport BOB — générant 15 avertissements parasites par exécution. Une liste blanche globale codée en dur serait incorrecte : ces binaires n'ont rien à faire sur un serveur de production. La configuration par utilisateur est la seule solution propre.

#### Implémentation

**`bob/config.py` — `UserConfig.get_suid_whitelist() -> list[str]`**

Nouveau helper qui lit la clé `suid_whitelist` dans `~/.config/bob/config.conf`, divise sur les virgules et retourne une liste de patterns glob nettoyés. Retourne `[]` quand la clé est absente ou vide. Suit le pattern existant des helpers `get_profile()` / `get_webhook_url()`.

```
# ~/.config/bob/config.conf
suid_whitelist = kismet_cap_*, mon_outil_maison
```

**`bob/checks/suid_audit.py` — `SuidSnapshot`**

- `SuidSnapshot` reçoit un nouveau champ `whitelisted_suid: list[str]` (défaut `[]`), stockant les chemins supprimés par les patterns utilisateur.
- `SuidSnapshot.from_system()` reçoit un paramètre `user_whitelist: list[str] | None = None`.
- Après le filtre sur `_KNOWN_SUID`, un second passage applique `fnmatch.fnmatch(basename, pattern)` pour chaque pattern utilisateur. Les chemins correspondants passent de `unexpected_suid` à `whitelisted_suid`.
- `check_suid_audit()` émet `suid_audit.whitelisted` (INFO) quand `snapshot.whitelisted_suid` est non vide, avec le nombre et les chemins. Intentionnellement visible — l'utilisateur doit voir que la suppression a eu lieu.

**`bob/runner.py`**

`SuidSnapshot.from_system(user_whitelist=user_config.get_suid_whitelist())` — la liste blanche est chargée depuis `user_config` (déjà dans scope) et passée à l'appel.

#### Décisions de conception

- **Glob sur le basename uniquement** : un matching sur le chemin complet permettrait à des patterns comme `*/opt/*` de supprimer tout ce qui est sous `/opt`. Le matching sur basename est prévisible et sûr.
- **INFO, pas invisible** : les chemins whitelistés sont rapportés en INFO plutôt que silencieusement supprimés. Si l'utilisateur whiteliste accidentellement `*`, il verra tous ses binaires SUID listés comme "supprimés par la liste blanche" et comprendra qu'il y a un problème.
- **Patterns séparés par virgules** : cohérent avec la façon dont la liste blanche `_KNOWN_SUID` fonctionne conceptuellement, et facilement éditable dans un fichier texte brut.

---

### Corrections — passe de code review (14 éléments)

Une revue systématique de la base de code a identifié et corrigé les problèmes suivants :

**BUG-2 — `compute_domain_scores()` non-idempotent (`domain_scores.py`)**
La fonction mutait `deduction.was_capped = True` sur des objets `Deduction` live. Un deuxième appel flipperait des flags supplémentaires sans raison. Correction : reset de tous les `was_capped = False` en début de `compute_domain_scores()` avant tout calcul.

**BUG-3 — `samba` et `desktop_apps` invisibles à `--check`/`--skip` (`runner.py`)**
Les deux sections étaient protégées par `_section_enabled()` mais absentes de `_ALL_SECTIONS`. `--list-checks` ne les montrait jamais ; `--check samba` était un no-op silencieux. Correction : les deux noms ajoutés à `_ALL_SECTIONS`.

**BUG-4 — Mode quiet contourné par toutes les lignes de statut (`output.py`)**
`_print_status()` et `print_risk_context()` utilisaient `print()` brut au lieu du wrapper `_p()` qui vérifie `_quiet`. Tous les `print_warn` / `print_alert` / `print_ok` / `print_info` atteignaient stdout même en mode `--quiet`. Correction : tous les `print()` remplacés par `_p()` dans ces deux fonctions.

**BUG-1 — Labels français codés en dur dans `output.py`**
`print_warn()` émettait `[ATTENTION]` et `print_alert()` émettait `[ALERTE]` inconditionnellement, même sur une install anglaise. Les clés i18n `status.warn = "WARNING"` et `status.alert = "ALERT"` existaient dans `locales/en.json` mais n'étaient jamais appelées. Correction : les deux fonctions appellent désormais `t("status.warn")` / `t("status.alert")` via un import local de `bob.i18n`.

**BUG-5 — Attribut dynamique `result._log_data` sur un dataclass (`scoring.py`, `checks/logs.py`, `display.py`)**
`check_logs()` posait un attribut `result._log_data` non déclaré avec `# type: ignore`. En cas de chemin d'early-return, `display_log_results()` n'affichait rien silencieusement. Correction : `CheckResult` reçoit un champ propre `log_data: dict | None = field(default=None)` ; `logs.py` et `display.py` mis à jour.

**BUG-6 — Déductions bruteforce sans `key=` (`checks/logs.py`)**
`result.warn()` et `result.add_deduction()` dans la boucle bruteforce n'avaient pas de `key=`, les rendant invisibles à `--ignore` et aux profils. Correction : `key="logs.brute_found"` ajouté aux deux appels.

**SF-1 — Parse de `sshd_config` silencieusement tronquée aux blocs `Match` (`checks/ssh.py`)**
Quand un bloc `Match` apparaissait dans `sshd_config`, les directives globales suivantes étaient silencieusement ignorées. Le check pouvait rapporter un faux OK. Correction : `_parse_config_file()` pose `config["_match_block"] = True` ; `_check_sshd_config()` émet `ssh.match_block_skipped` (INFO).

**SF-2 — `curr_baseline` potentiellement non lié (`__main__.py`)**
`curr_baseline` était assigné à l'intérieur d'un bloc `with redirect_stdout(...)`. Un futur refactoring qui briserait le couplage `diff_mode` provoquerait une `UnboundLocalError`. Correction : `curr_baseline = None` initialisé avant le bloc.

**SEC-1 — `fixes.py` ignore `--no-color` (`fixes.py`)**
Tous les literals `\033[...]` dans `fixes.py` contournaient le flag `--no-color` et l'infrastructure `output._c`. Rediriger la sortie des fixes vers un fichier produisait des séquences d'échappement brutes. Correction : tous les literals remplacés par `output._c.*`.

**BP-2 — Module externe écrivait sur des attributs `_privés` du moteur (`scoring.py`, `domain_scores.py`)**
`apply_domain_score_override()` posait directement `engine._domain_scores` et `engine._active_domains`, couplant `domain_scores.py` aux internals de `ScoreEngine`. Correction : méthode publique `ScoreEngine.set_domain_scores(scores, active)` ajoutée.

**BP-3 — Comparaison de chaîne sur la valeur d'un enum (`checks/ssh.py`)**
`f.level.value in ("warn", "alert", "info")` se briserait silencieusement si un membre de `FindingLevel` était renommé. Correction : `f.level != FindingLevel.OK`.

**BP-1 — `open(os.devnull)` sans `encoding=` (`__main__.py`)**
Ouverture de fichier en mode texte sans encodage explicite. Correction : `encoding="utf-8"` ajouté.

**INC-2 — `snapshot.from_system()` s'exécutait avant le guard `_section_enabled()` (`runner.py`)**
`SambaSnapshot.from_system()` et `DesktopAppsSnapshot.from_system()` (qui exécutent des requêtes `dpkg`/subprocess) étaient appelés inconditionnellement, même lors d'un `--skip`. Correction : appels `from_system()` déplacés à l'intérieur du guard `_section_enabled()`.

**DC-1 — `_is_root_owned()` code mort (`checks/suid_audit.py`)**
Helper privé jamais appelé en production ; la logique inline à la ligne 165 faisait déjà la même chose. Correction : fonction supprimée, ses deux tests unitaires supprimés.

---

## [v0.3.1] — 06-05-2026

Deux corrections de bugs identifiées lors de la validation multi-VM, plus deux refactorisations architecturales dans le pipeline de décomposition du score. Aucune nouvelle fonctionnalité. 4328/4328 tests (+6).

---

### Correction 1 — Version bannière bloquée à `0.2.4` (`bob/__init__.py`)

#### Problème

Après la sortie de v0.3.0, `bob/__init__.py` déclarait encore `__version__ = "0.2.4"`. La bannière ASCII affichée par `print_banner()` et la sortie de `bob -V` / `bob --version` lisent toutes deux la version depuis cet attribut de module, donc toutes les plateformes affichaient `BOB v0.2.4` au lieu de `BOB v0.3.0`. Découvert immédiatement lors du premier audit VM post-v0.3.0.

#### Correction

`__version__ = "0.2.4"` → `"0.3.1"`. Aucun autre changement de code — la chaîne de version est l'unique source de vérité pour la bannière, le flag de version, et le champ `meta.version` de la sortie JSON.

---

### Correction 2 — Contexte réseau DDNS non propagé vers l'entête du score (`bob/runner.py`, `bob/__main__.py`)

#### Problème

`run_checks()` appelle `ddns_effective_context()` en interne pour upgrader `network_context` de `"local"` à `"ddns"` quand un client DDNS actif est détecté avec des ports ouverts. La fonction retournait correctement, mais `ChecksResult` — le NamedTuple retourné par `run_checks()` — ne contenait pas de champ `network_context`. `__main__.py` utilisait donc toujours sa valeur initiale (`"local"`) pour l'entête du résumé et l'affichage d'exposition, quels que soient les résultats du check DDNS.

L'effet : les machines faisant tourner ddclient/inadyn/No-IP/DuckDNS avec des ports ouverts affichaient "Réseau local uniquement" dans l'entête du score au lieu de "Exposition publique via DDNS". Le calcul du score lui-même était correct (la pénalité d'exposition est appliquée dans `run_checks()` avant que la valeur du contexte importe pour l'affichage), seule l'étiquette de l'entête était erronée.

Découvert lors de la validation de la VM Kali avec un client DDNS actif.

#### Correction

`network_context: str = "local"` ajouté comme dernier champ de `ChecksResult`. L'instruction `return ChecksResult(...)` dans `run_checks()` inclut désormais `network_context=network_context`. Dans `__main__.py`, `network_context = result.network_context` est assigné immédiatement après `result = run_checks(...)`, remplaçant la variable locale obsolète.

---

### Refactorisation 1 — `was_capped: bool` sur `Deduction` (`bob/scoring.py`, `bob/domain_scores.py`, `bob/breakdown.py`)

#### Problème

`bob/breakdown.py` déclare dans son docstring de module : *"Nothing is computed here — all data comes from the already-finalized engine."* Pourtant, la section de résumé des plafonds outil ré-implémentait le calcul des plafonds depuis zéro, maintenant un dict `tool_contributed` local et itérant deux fois sur le breakdown pour identifier les entrées plafonnées. Cela dupliquait la logique de `compute_domain_scores()` et constituait une source latente de divergence.

#### Correction

`Deduction` (dans `bob/scoring.py`) gagne `was_capped: bool = False`. `compute_domain_scores()` (dans `bob/domain_scores.py`) positionne `deduction.was_capped = True` à deux endroits :

- Quand `allowed <= 0` (totalement absorbé — la déduction ne contribue rien à son domaine).
- Quand `allowed < points` (partiellement absorbé — seule une partie de la déduction est comptée).

`breakdown.py` lit `d.was_capped` directement dans la boucle du tableau de déductions (pour l'annotation `[plafonné]`) et utilise une compréhension d'ensemble sur `d.was_capped` pour construire l'ensemble `capped_prefixes` pour le résumé des plafonds outil. Le suivi local `tool_contributed` et `capped_entries` est supprimé entièrement.

---

### Refactorisation 2 — Propriétés `engine.domain_scores` / `engine.active_domains` en cache (`bob/scoring.py`, `bob/domain_scores.py`, `bob/__main__.py`, `bob/breakdown.py`)

#### Problème

Après `apply_domain_score_override()`, les scores par domaine et l'ensemble de domaines actifs sont stables — ils ne changeront plus. Pourtant `__main__.py` et `breakdown.py` importaient et appelaient `compute_domain_scores()` et `active_domains_from_engine()` séparément, ce qui entraînait un double calcul par audit. Toute divergence future entre les deux sites d'appel produirait un affichage incohérent.

#### Correction

`ScoreEngine.__init__()` initialise deux caches privés : `_domain_scores: dict | None = None` et `_active_domains: frozenset | None = None`. `apply_domain_score_override()` leur assigne les résultats après calcul :

```python
engine._domain_scores  = scores
engine._active_domains = active
```

Deux méthodes `@property` les exposent :

```python
@property
def domain_scores(self) -> dict:
    return self._domain_scores or {}

@property
def active_domains(self) -> frozenset:
    return self._active_domains or frozenset()
```

`__main__.py` et `breakdown.py` basculent tous deux vers `engine.domain_scores` et `engine.active_domains`. Les imports directs de `compute_domain_scores` et `active_domains_from_engine` sont supprimés de `__main__.py`.

---

### Tests

4328/4328 (+6 nouveaux) :

| Fichier | Classe | Test | Couverture |
|---------|--------|------|------------|
| `tests/test_domain_scores.py` | `TestWasCapped` | `test_uncapped_deduction_not_marked` | Déduction dans le plafond → `was_capped` reste `False` |
| `tests/test_domain_scores.py` | `TestWasCapped` | `test_fully_absorbed_deduction_marked` | Déduction après épuisement du plafond → `was_capped = True` |
| `tests/test_domain_scores.py` | `TestWasCapped` | `test_partially_absorbed_deduction_marked` | Déduction dépasse le plafond restant → `was_capped = True` |
| `tests/test_domain_scores.py` | `TestWasCapped` | `test_non_tool_cap_key_never_marked` | Clé sans préfixe de plafond outil → `was_capped` toujours `False` |
| `tests/test_domain_scores.py` | `TestWasCapped` | `test_cached_domain_scores_on_engine` | Après surcharge, `engine.domain_scores` correspond à `compute_domain_scores()` |
| `tests/test_domain_scores.py` | `TestWasCapped` | `test_engine_domain_scores_empty_before_override` | Avant surcharge, `engine.domain_scores` retourne `{}` |

---

## [v0.3.0] — 06-05-2026

Jalon transparence du scoring. Nouvelle option `--breakdown` (`-B`) affichant le chemin complet de calcul du score après un audit. `--explain <clé>` gagne une section SCORING. Trois corrections ciblées : asymétrie `-unsigned` dans la logique de rétention des kernels, flèche `→` orpheline sur les deltas de score stables, et reliques "UFW-AU" dans le rapport détaillé. 4322/4322 tests (+48).

---

### Fonctionnalité 1 — option `--breakdown` / `-B` (`bob/breakdown.py`, `bob/cli.py`, `bob/__main__.py`, `bob/locales/en.json`, `bob/locales/fr.json`)

#### Motivation

Le scoring de BOB utilise un pipeline multicouche : déductions par vérification → plafonds par outil → plafond moteur → surcharge de moyenne par domaine. Le score final était visible mais pas sa dérivation. Les utilisateurs voyant un 6/10 n'avaient aucun moyen de comprendre quelles déductions avaient contribué, si un plafond avait été déclenché, ou comment la moyenne par domaine avait modifié le résultat.

#### Implémentation

Nouveau module `bob/breakdown.py` — `display_breakdown(engine, t, output_mod)` — lit le `ScoreEngine` déjà finalisé et affiche :

1. **Déductions** — tableau complet (clé · domaine · points · contexte), avec annotation `[plafonné]` pour les entrées absorbées par un plafond outil.
2. **Plafonds par outil** — une ligne `[INFO]` par outil où les déductions brutes totales dépassent le plafond.
3. **Plafond moteur** — ligne `[ATTENTION]` si `engine.cap_info` est défini (ex. "pare-feu inactif — plafond à 3").
4. **Score brut** — `engine._raw_score` avant la moyenne par domaine.
5. **Scores par domaine** — chaque domaine actif avec score, déductions, et barre de progression sur 10 caractères.
6. **Surcharge de moyenne** — ligne `[INFO]` montrant la moyenne calculée et le nombre de domaines actifs, quand `engine._global_override is not None`.
7. **Score final** — coloré : vert (≥ 8), jaune (≥ 5), rouge (< 5).

Les labels de domaine sont traduits via `_domain_label(domain_id, t)` — essaie d'abord `t(f"domain_scores.{domain_id}")` (même pattern que `render_domain_scores`), se rabat sur `_LABELS` puis `domain_id.capitalize()`. Cela assure l'apparition des labels français (ex. "Durcissement") lors de l'exécution avec `--french`.

**Gestion de stdout** — `breakdown_mode` est ajouté à `_silent_mode` dans `__main__.py`. Tout l'audit s'exécute dans `with redirect_stdout(devnull)`, supprimant tous les appels `print()` nus (pas seulement les appels `output.*`, déjà supprimés par `quiet=True`). Après le bloc `with`, stdout est restauré et `display_breakdown` est appelé avec `output` réinitialisé sans `quiet`. C'est le même pattern qu'utilise `diff_mode` et les formats lisibles par machine.

#### i18n

Nouvelle section `breakdown.*` dans les deux fichiers de locales :

| Clé | Rôle |
|-----|------|
| `breakdown.section_title` | En-tête de section |
| `breakdown.no_deductions` | Message OK quand aucune déduction |
| `breakdown.deductions_header` | Sous-en-tête "N déduction(s) :" |
| `breakdown.capped` | Annotation pour les entrées plafonnées |
| `breakdown.tool_cap_applied` | Ligne info plafond outil |
| `breakdown.engine_cap_applied` | Ligne attention plafond moteur |
| `breakdown.raw_score` | Ligne score brut |
| `breakdown.domain_scores_header` | Sous-en-tête scores par domaine |
| `breakdown.domain_average` | Ligne surcharge moyenne domaine |
| `breakdown.final_score` | Ligne score final |

#### CLI

`-B` / `--breakdown` ajouté à `bob/cli.py` comme option booléenne. `_silent_mode` dans `__main__.py` étendu : `_machine_mode or config.breakdown_mode or config.diff_mode`.

---

### Fonctionnalité 2 — `--explain` score-aware (`bob/explain.py`)

#### Problème

`bob --explain <clé>` affichait les étapes de remédiation mais ne donnait aucune indication sur la contribution de la clé au score — son domaine d'appartenance, si un plafond outil limitait ses déductions, ou comment voir son impact en direct.

#### Correction

Nouvelle fonction `_explain_scoring(key, t)` ajoutée à la fin de chaque appel `run_explain()`. Lit `_key_to_domain(key)` et `_TOOL_CAPS.get(prefix)` depuis `bob/domain_scores.py` et affiche :

```
SCORING
────────────────────────────────────────
  Domain   : Durcissement
  Tool cap : max 2 pt total for 'hardening' deductions in this domain
  Impact   : run 'sudo bob --breakdown' to see this key's current score contribution
```

Les clés sans mapping de domaine (ex. clés info génériques) ignorent silencieusement la section.

---

### Correction 1 — Asymétrie de rétention kernel `-unsigned` (`bob/checks/kernel_modules.py`, `tests/test_kernel_modules.py`)

#### Problème

Sur les systèmes Debian, les paquets kernel signés et non-signés sont installés côte à côte :

```
linux-image-6.12.74+deb13+1-amd64
linux-image-6.12.74+deb13+1-amd64-unsigned
```

`_kernel_sort_key()` produit des tuples numériques identiques pour les deux (même `MAJOR.MINOR.PATCH+ABI`). Quand les tuples sont égaux, le tri de Python est stable, ce qui fait que la variante non-signée (apparaissant plus tard dans la sortie dpkg) se retrouve en dernière position dans la liste triée et devient `most_recent`.

La boucle de rétention remplit les slots du plus récent vers le plus ancien. Avec trois kernels installés et `keep_count=3` (profil server), la boucle remplit : `running`, `most_recent` (non-signé), et un kernel plus ancien. La variante signée de la même version que `most_recent` n'obtient pas de slot et atterrit dans `to_remove` — incorrectement marquée comme obsolète.

#### Correction

Après la boucle de rétention, étendre l'ensemble de conservation pour inclure les deux variantes de chaque version de base conservée :

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

`_strip_unsigned()` existait déjà dans le module. Cette expansion est O(keep_count) et s'exécute une seule fois après la boucle.

De plus, le message de détail des kernels obsolètes a été modifié de `recent=most_recent` à `recent=running`. Le conseil de vérification après redémarrage ("vérifiez que le système démarre correctement avant de supprimer les anciens kernels") doit référencer le kernel effectivement en cours d'exécution, pas le sibling `-unsigned` qui trie en dernier par hasard.

---

### Correction 2 — Flèche `→` orpheline dans le delta de score (`bob/display.py`)

#### Problème

Dans `print_audit_summary()`, la ligne de score est construite ainsi :

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

Quand le score était identique (`delta == 0`), la ligne affichait `6/10  →` sans rien après la flèche. La flèche était censée indiquer "stable" mais ressemblait à une ligne tronquée dans l'affichage de la boîte.

#### Correction

```python
    else:
        score_str += f"  = {score}"
```

"= 6" est sans ambiguïté : le score est égal à la valeur précédente.

---

### Correction 3 — Reliques "UFW-AU" dans le rapport détaillé (`bob/report.py`, `bob/report_markdown.py`)

#### Problème

`AuditReport.write_header()` contenait des tableaux de lettres ASCII codés en dur représentant "UFW-AU" — l'acronyme de l'ancien nom d'outil "ufw-audit". La liste de groupes de lettres était `[U, F, W, TIRET, A, U]`. L'en-tête imprimait aussi `UFW : ufw {version}` précédé de l'étiquette `UFW`.

Dans `report_markdown.py`, l'entrée pare-feu était étiquetée `**UFW:**`.

#### Correction

`bob/report.py` — groupes de lettres remplacés par `[B, O, B]` en utilisant la même police Doom block déjà utilisée dans le bandeau terminal de `output.py`. Étiquette d'en-tête changée en `Firewall : ufw {info.ufw_version}`.

`bob/report_markdown.py` — étiquette changée en `**Firewall (UFW):**`.

---

### Tests

4322/4322 (+48 nouveaux) :

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

#### `tests/test_min_level.py` (mis à jour, 0 nouveau net)

`test_stable_shows_right_arrow` renommé en `test_stable_shows_equal` ; assertion mise à jour de `"→" in val` vers `"= 7" in val`. Docstring du module mis à jour en conséquence.

---

## [v0.2.4] — 05-05-2026

Passe de durcissement du codebase post-audit, déclenchée par une revue systématique de l'ensemble du projet à la suite de la tournée multi-VM v0.2.3. Deux bugs UX kernel Debian `-unsigned` corrigés, une régression dans le pattern sentinel `deduction_total` résolue, les annotations de type propagées à toutes les signatures de vérification, la détection des opérateurs shell durcie, et le fallback de profil rendu visible. Aucun nouveau check, aucun changement comportemental. 4274/4274 tests (+12).

---

### Fix 1 — `kernels_up_to_date` nomme le kernel courant, pas le sibling `-unsigned` (`bob/checks/kernel_modules.py`, `tests/test_kernel_modules.py`)

#### Problème

Sur les systèmes Debian avec les deux variantes d'un package kernel installées (ex. `linux-image-6.12.74+deb13+1-amd64` et `linux-image-6.12.74+deb13+1-amd64-unsigned`), `_kernel_sort_key()` les trie alphabétiquement après correspondance sur le même préfixe numérique. La variante non-signée se retrouve en dernière position et devient `most_recent`.

Dans `_check_installed_kernels()`, le message OK "kernel à jour" passait `version=most_recent` :

```python
result.ok(
    message=_t("kernel_modules.kernels_up_to_date", version=most_recent),
    ...
)
```

Quand `running = "6.12.74+deb13+1-amd64"` et `most_recent = "6.12.74+deb13+1-amd64-unsigned"`, le message affiché nommait le sibling `-unsigned` plutôt que le kernel dans lequel le système avait réellement démarré.

#### Correction

```python
result.ok(
    message=_t("kernel_modules.kernels_up_to_date", version=running),
    ...
)
```

Le message nomme maintenant toujours le kernel courant, quelle que soit la variante triée en dernier.

---

### Fix 2 — Bon template de message pour les paires signées/non-signées (`bob/checks/kernel_modules.py`, `tests/test_kernel_modules.py`)

#### Problème

`_check_installed_kernels()` sélectionne entre deux templates de message i18n :

- `kernels_obsolete_same` — utilisé quand `running == most_recent` (le kernel courant est le plus récent ; certains anciens peuvent être nettoyés). Pas de paire "courant / récent" dans le texte.
- `kernels_obsolete` — utilisé quand `running != most_recent` (un redémarrage mettrait à jour le kernel). Inclut les deux versions dans le texte.

La comparaison était littérale :

```python
if running == most_recent:
    _msg = _t("kernel_modules.kernels_obsolete_same", ...)
else:
    _msg = _t("kernel_modules.kernels_obsolete", ...)
```

Sur Debian avec une paire signé/non-signé, `running = "6.12.74+deb13+1-amd64"` et `most_recent = "6.12.74+deb13+1-amd64-unsigned"`. Ce sont sémantiquement la même version de kernel (même ABI, même niveau de sécurité), mais la comparaison littérale retourne `False`. L'outil utilisait incorrectement `kernels_obsolete`, sous-entendant que l'utilisateur devait redémarrer pour appliquer un kernel plus récent — factuellement faux.

`_strip_unsigned()` existait déjà dans le module précisément pour cette normalisation mais n'était pas appliqué dans ce chemin de code.

#### Correction

```python
if _strip_unsigned(running) == _strip_unsigned(most_recent):
    _msg = _t("kernel_modules.kernels_obsolete_same", ...)
else:
    _msg = _t("kernel_modules.kernels_obsolete", ...)
```

Les deux côtés sont normalisés avant la comparaison. Une paire signé/non-signé sélectionne maintenant correctement `kernels_obsolete_same`.

---

### Fix 3 — Sentinel `None` pour `deduction_total` évite un faux delta lors de la mise à jour (`bob/compare.py`, `tests/test_compare.py`)

#### Problème

v0.2.3 a introduit `deduction_total: int = 0` dans `AuditBaseline` et affichait un message "Déductions variables ±N pt(s)" dans `display_delta()` quand `deduction_delta != 0`. La valeur par défaut était `0`, et `load_baseline()` utilisait :

```python
deduction_total=int(raw.get("deduction_total", 0))
```

Les fichiers JSON de baseline pré-v0.2.3 ne contiennent pas la clé `"deduction_total"`. L'appel retournait `0`. Au premier audit suivant, `deduction_delta = curr.deduction_total - 0`. Comme `curr.deduction_total` est presque toujours positif (il y a presque toujours des déductions), le message des déductions variables apparaissait à chaque première exécution après une mise à jour depuis un baseline pré-v0.2.3 — un faux positif : rien n'avait réellement changé, le champ n'existait simplement pas dans l'ancien baseline.

C'est exactement le même mode d'échec que celui déjà résolu pour `finding_keys` avec le sentinel `list[str] | None = None`.

#### Correction

```python
# AuditBaseline
deduction_total: int | None = None   # None = baseline pré-v0.2.3 (champ absent)

# load_baseline()
deduction_total=int(raw["deduction_total"]) if isinstance(raw.get("deduction_total"), int) else None,

# compute_delta()
deduction_delta=(
    curr.deduction_total - prev.deduction_total
    if prev.deduction_total is not None and curr.deduction_total is not None
    else 0
),
```

`None` signifie "l'audit précédent est antérieur à l'introduction du champ". Le calcul du delta est ignoré pour ces baselines, produisant `deduction_delta = 0` et supprimant le message. Les nouveaux baselines écrivent toujours un entier ; les comparaisons suivantes se comportent normalement.

---

### Fix 4 — Alias de type `TranslationFunc` sur toutes les signatures de check (`bob/checks/_run.py`, 42 fichiers)

#### Problème

La fonction de traduction `t` était passée en argument nommé à toutes les fonctions `check_*` avec l'annotation `t=None` (non typée). Les vérificateurs de type ne pouvaient pas inférer la signature de l'appelable, et les IDEs n'offraient pas de complétion pour des appels comme `_t("clé", param=valeur)`. Il n'existait pas non plus de lieu unique pour documenter le contrat de la fonction.

#### Correction

`bob/checks/_run.py` (déjà importé par chaque module de check) gagne :

```python
from typing import Callable

TranslationFunc = Callable[..., str]
"""Type alias pour la fonction de traduction de BOB : t(key, **kwargs) -> str."""
```

Les 42 signatures de fonctions `check_*` dans 40 fichiers de checks, `bob/history.py` et `bob/plugin_checks.py` sont mises à jour :

```python
# Avant
def check_firewall(snapshot, *, t=None, ...):

# Après
def check_firewall(snapshot, *, t: TranslationFunc | None = None, ...):
```

Les deux occurrences restantes de `t=None` sont des fonctions auxiliaires privées (`_check_installed_kernels`, `_check_exposure`) où l'annotation ajouterait du bruit sans bénéfice.

---

### Fix 5 — `_has_shell_ops()` via tokenisation `shlex` (`bob/fixes.py`)

#### Problème

`_run_fix()` utilisait la correspondance par sous-chaîne pour décider si une commande de remédiation nécessitait `shell=True` :

```python
_SHELL_OPS = ("&&", "||", "|", ";", ">", ">>")

if any(op in cmd for op in _SHELL_OPS):
    subprocess.run(cmd, shell=True, ...)
else:
    subprocess.run(shlex.split(cmd), shell=False, ...)
```

`op in cmd` correspond partout dans la chaîne, y compris dans les arguments entre guillemets et les chemins de fichiers. Une commande avec un chemin contenant `>` ou un argument de type `--format=json>output` serait incorrectement routée vers `shell=True`, introduisant une surface d'injection shell inutile.

#### Correction

```python
def _has_shell_ops(cmd: str) -> bool:
    """Retourne True si cmd contient des opérateurs shell nécessitant shell=True."""
    _SHELL_TOKENS = frozenset({"&&", "||", ";", "|", ">", ">>", "<", "&"})
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return True   # guillemets malformés — traité comme non sûr
    return any(tok in _SHELL_TOKENS or tok.startswith("`") or tok.startswith("$(")
               for tok in tokens)
```

`shlex.split()` tokenise la commande comme le ferait un shell POSIX, en retirant les guillemets sans rien substituer. Les opérateurs ne sont correspondus qu'en tant que tokens complets. Les guillemets malformés retournent prudemment `True` plutôt que de lever une exception.

---

### Fix 6 — Fallback de profil maintenant visible (`bob/__main__.py`, locales)

#### Problème

`load_profile()` retournait silencieusement le profil `server` par défaut quand le nom de profil demandé n'était pas trouvé. Quand un utilisateur passait `--profile=laptop` (profil inexistant), l'audit s'exécutait avec le profil `server` sans aucune indication dans la sortie. L'utilisateur ne pouvait pas distinguer "profil actif" de "profil ignoré silencieusement".

#### Correction

```python
active_profile = load_profile(profile_name)
if profile_name not in ("", "default", "server") and active_profile.name != profile_name:
    output.print_warn(t("audit.profile_not_found", profile=profile_name))
```

La garde exclut les alias du profil par défaut (`""`, `"default"`, `"server"`) pour éviter les avertissements parasites quand aucun profil n'est spécifié. Nouvelles clés i18n :

- `en.json` : `"profile_not_found": "Profile '{profile}' not found — using default (server)"`
- `fr.json` : `"profile_not_found": "Profil '{profile}' introuvable — utilisation du profil par défaut (server)"`

---

### Tests

4274/4274 (+12 nouveaux, tous verts) :

| Fichier | Tests ajoutés |
|---------|--------------|
| `tests/test_kernel_modules.py` | `test_up_to_date_names_running_kernel_not_unsigned_sibling` — asserte le nom du kernel courant dans le message OK, pas le sibling `-unsigned` |
| `tests/test_kernel_modules.py` | `test_debian_signed_unsigned_pair_uses_obsolete_same_message` — asserte la clé `kernels_obsolete_same` quand une paire signé/non-signé est au sommet |
| `tests/test_compare.py` | `test_variable_deductions_increased_shown_without_structural_change` |
| `tests/test_compare.py` | `test_variable_deductions_decreased_shown_without_structural_change` |
| `tests/test_compare.py` | `test_variable_deductions_suppressed_when_warn_delta` |
| `tests/test_compare.py` | `test_variable_deductions_suppressed_when_new_finding_key` |
| `tests/test_compare.py` | `test_deduction_total_none_in_new_baseline_defaults` — le défaut de `AuditBaseline()` est `None` |
| `tests/test_compare.py` | `test_load_baseline_returns_none_when_field_absent` — ancien JSON sans champ → `None` |
| `tests/test_compare.py` | `test_load_baseline_returns_int_when_field_present` — nouveau JSON avec champ → entier |
| `tests/test_compare.py` | `test_deduction_delta_zero_when_prev_is_old_baseline` — prev `None` → delta = 0 |
| `tests/test_compare.py` | `test_deduction_delta_computed_when_both_tracked` — deux entiers → delta correct |
| `tests/test_compare.py` | `test_deduction_delta_zero_when_unchanged` — même valeur des deux côtés → 0 |

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

## [v0.1.0] — 26-04-2026

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

---

© 2026 Cédric Clauzel
