*[Read in English](CHANGELOG_FULL.md)* · *[TL;DR](../CHANGELOG_FR.md)*

# BOB — Bodyguard Of Bits — Journal des modifications

Toutes les modifications notables du projet sont documentées ici.

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
