*[Read in English](CHANGELOG.md)* · *[Journal complet](DOCUMENTS/CHANGELOG_FULL_FR.md)*

# BOB — Journal des modifications

| Version | Date | Résumé |
|---------|------|--------|
| [v0.2.3](#v023) | 03-05-2026 | Corrections tournée multi-VM : NOT_LISTENING WARN→INFO · déduction IoT supprimée · affichage heredoc · garde symlink circulaire · Python 3.9 retiré · delta déductions compare · label SSH surface d'attaque · label active_disabled · 4262/4262 tests (+1) |
| [v0.2.2](#v022) | 02-05-2026 | Corrections scoring : `ScoreCap.key` · domaines INFO exclus · ClamAV 1pt · logging uniformisé · check règle UFW sans protocole · fix plafond domaine · fix locale SSH detail · tests invariants scoring · 4261/4261 tests (+23) |
| [v0.2.1](#v021) | 02-05-2026 | Hotfix — passe défensive : crash fix `--manage-logs` · 8 `except Exception` resserrés · 5 regex en module-level · regex email dédupliqué · `getattr` supprimé du scoring |
| [v0.2.0](#v020) | 01-05-2026 | Refonte du scoring (moyenne domaines · plafond par outil) · détection MTA cron · faux positif kernel `-unsigned` · dominance IoT WARN · bannière orange · 4238/4238 tests |
| [v0.1.1](#v011) | 29-04-2026 | Hotfix — parser fwupd format arbre · message `--install-completion` · renommage colonne panorama · 4206/4206 tests |
| [v0.1.0](#v010) | 26-04-2026 | Version initiale — 46 vérifications · 9 domaines · 32 services · mapping CIS · FR/EN · 4200/4200 tests |

---

## [v0.2.3] — 03-05-2026

Huit corrections identifiées lors d'une tournée d'audit multi-VM (Linux Mint, Debian 13, Kali, Ubuntu 26.04). Trois corrections comportementales, deux corrections infrastructure, trois corrections de précision UX. 4262/4262 tests (+1).

### Corrections de bugs — tournée multi-VM (`bob/checks/services.py`, `bob/checks/logs.py`, `bob/display.py`)

**Fix 1 — NOT_LISTENING toujours INFO** — Les ports présents dans le registre de services mais sans écoute active (ex. Mosquitto 8883 quand seul 1883 est lié) étaient affichés en `⚠ [ATTENTION]` pour les services CRITIQUE/ÉLEVÉ, apparaissant dans la boîte résumé. Corrigé : `NOT_LISTENING` émet maintenant toujours `result.info()` quelle que soit la sévérité du service. Tests renommés : `test_not_listening_critical_adds_info`, `test_not_listening_high_adds_info`.

**Fix 2 — Dominance locale IoT : déduction supprimée** — Quand une seule IP privée dominait les logs UFW bloqués (trafic IoT typique), l'outil émettait `result.warn(nature="improvement")` et déduisait 1 point. Un trafic bénin en provenance d'une source privée connue ne devrait pas réduire le score. Corrigé : rétrogradé en `result.info()` sans déduction. Tests : `test_finding_is_info_level`, `test_no_score_deduction`.

**Fix 3 — Heredoc non tronqué** — Les commandes multi-lignes (blocs heredoc dans les étapes de remédiation auditd) étaient passées à `_wrap_for_box()` via `text.split()`, qui supprimait tous les retours à la ligne. Corrigé : `_add_finding_lines()` itère maintenant `item.cmd.splitlines()` et appelle `_wrap_for_box()` par ligne, préservant visuellement la structure heredoc.

### Infrastructure

**`bob/completion.py` — garde contre les symlinks circulaires** — `--install-completion` créait un symlink circulaire (`~/.local/bin/bob → lui-même`) quand pipx était installé en root et que le chemin utilisateur était déjà un lien vers le chemin système. Corrigé : garde `candidate.resolve() != dst_bin.resolve()` ajouté. `exists()` retourne déjà `False` pour les symlinks cassés ; la vérification resolve empêche le cas circulaire.

**Python 3.9 retiré** (`pyproject.toml`, `.github/workflows/tests.yml`, `.github/workflows/publish.yml`) — Python 3.9 a atteint sa fin de vie en octobre 2025. `requires-python` passé à `">=3.10"`. Classifier et entrées de la matrice CI supprimés.

### Corrections de précision UX — tests multi-distros

**Compare : delta de déductions variables** (`bob/compare.py`) — Quand le score changeait entre deux audits sans nouvelle clé de finding (ex. activité log variable entre runs), la section CHANGEMENTS n'affichait que "Score dégradé de N point(s)" sans plus d'explication. Ajout de `deduction_total: int` dans `AuditBaseline` et `deduction_delta: int` dans `AuditDelta`. Quand `deduction_delta != 0` et qu'aucun changement structurel (count alertes/warns, clés findings) n'explique le mouvement de score, affiche "Déductions variables ±N pt(s) (logs, trafic réseau)". Les anciens baselines (champ absent) ont `deduction_total=0` par défaut et ne produisent aucun faux delta. Trouvé sur : VM Debian 13, VM Kali.

**Surface d'attaque : label SSH scindé** (`bob/exposure.py`) — Le tableau de surface d'attaque utilisait une seule clé i18n (`ssh_not_running` = "non installé / non démarré") pour les deux cas "SSH non installé" et "SSH installé mais arrêté". Quand SSH était installé mais inactif (ex. Kali), le label était factuellement incorrect. Scindé en `ssh_not_installed` ("non installé") et `ssh_stopped` ("installé — non démarré"), utilisés par les branches de code respectives. Nouveau test : `test_not_active_shows_stopped_text`. Trouvé sur : VM Kali.

**Services : message `active_disabled` avec label du service** (`bob/checks/services.py`) — "Le service est actif en ce moment, mais ne redémarrera pas automatiquement." apparaissait dans la boîte résumé sans identifier quel service. Le nom est visible dans l'audit complet sous l'en-tête `▶ Service`, mais perdu lors de la promotion en résumé. Corrigé : `{label}` ajouté à la chaîne i18n ; `label=snap.label` passé au site d'appel. Trouvé sur : VM Linux Mint (Redis).

### Tests

4262/4262 (+1 nouveau, 4 renommés/mis à jour) :

| Fichier | Modification |
|---------|-------------|
| `tests/test_services.py` | Renommés : `test_not_listening_critical_adds_warn` → `_adds_info` · `test_not_listening_high_adds_warn` → `_adds_info` · assertions mises à jour niveau `info` |
| `tests/test_logs.py` | Renommés : `test_finding_is_warn_level` → `_info_level` · `test_score_deduction_one_point` → `test_no_score_deduction` · assertions mises à jour |
| `tests/test_exposure.py` | Mis à jour : `test_not_installed_info_is_ok` et `test_not_installed_overrides_password_auth` assertent la clé `ssh_not_installed` · +1 nouveau `test_not_active_shows_stopped_text` |

---

## [v0.2.2] — 03-05-2026

Cinq corrections ciblées du scoring, un fix de locale, uniformisation du logging, couverture de test pour le fix de race condition v0.2.1, tests d'invariants scoring, documentation de la pondération égale des domaines, et correction du check de règle UFW sans protocole. 4261/4261 tests (+23).

### Corrections scoring (`bob/scoring.py`, `bob/domain_scores.py`, `bob/checks/clamav.py`)

**Fix 1 — Propagation `ScoreCap.key`** — `ScoreCap` gagne un champ `key: str = ""`. Les méthodes `set_cap()`, `cap()`, `apply()` et `finalize()` le propagent toutes. La `Deduction` synthétique émise quand un plafond se déclenche porte maintenant `key=self._cap.key` au lieu de `key=""`, permettant l'attribution correcte au domaine. Mis à jour : `bob/checks/firewall.py` passe `key="firewall.inactive"` à `result.set_cap()`.

**Fix 2 — Les findings INFO n'inflatent plus l'ensemble des domaines actifs** — `active_domains_from_engine()` ne compte maintenant que les findings WARN et ALERT pour déterminer quels domaines sont « actifs » dans la moyenne globale. Un domaine INFO-only (service installé, rien d'actionnable) n'est plus inclus dans la moyenne. `FindingLevel` importé directement depuis `bob.scoring`.

**Fix 3 — `clamav.db_very_outdated` 2pt → 1pt** — La déduction était de 2 pts mais le plafond outil `clamav` dans `_TOOL_CAPS` est de 1 pt. Le point excédentaire n'affectait que `engine._raw_score`, créant une asymétrie silencieuse entre score brut et score par domaine. Réduit à 1 pt pour éliminer ce point fantôme.

### Observabilité — logging uniformisé (`bob/history.py`, `bob/ignore.py`, `bob/sysinfo.py`)

`except … pass` remplacé par `_log.debug()` dans 6 emplacements sur 3 modules. `import logging` + `_log = logging.getLogger(__name__)` ajoutés à chacun. Les échecs restent non-fatals ; visibles avec `--debug`.

| Module | Fonction | Exception | Message |
|--------|----------|-----------|---------|
| `bob/history.py` | `save_score()` | `OSError` | `"Failed to save score to history: …"` |
| `bob/history.py` | `_rotate_if_needed()` | `OSError` | `"Failed to rotate history file: …"` |
| `bob/ignore.py` | `load_ignore_keys()` | `OSError` | `"Cannot read ignore file …: …"` |
| `bob/sysinfo.py` | `get_user_home()` | `KeyError` | `"SUDO_USER … not found in password database, falling back to Path.home()"` |
| `bob/sysinfo.py` | `collect_system_info()` | `OSError` | `"Cannot read /etc/os-release: …"` |
| `bob/sysinfo.py` | `detect_network_type()` ×2 | `subprocess.TimeoutExpired / FileNotFoundError / OSError` | `"ip route failed …"` / `"ip addr failed …"` |

### Contrat scoring documenté (`bob/scoring.py`)

La docstring de `finalize()` documente la séquence obligatoire : `engine.finalize()` → `apply_domain_score_override(engine)`. `set_global_score()` marqué « ne pas appeler directement ». Précise que `engine._raw_score` reste accessible pour le débogage.

### Fix 4 — Plafond de domaine non appliqué si le score brut global est déjà sous le seuil (`bob/domain_scores.py`)

`compute_domain_scores()` calcule le score de chaque domaine à partir des déductions présentes dans `engine.breakdown`. Quand un plafond se déclenche (ex. `firewall.inactive` → max 3/10), `finalize()` ajoute un delta de déduction dans `breakdown` **seulement si** `raw_global_score > cap.maximum`. Sur un système cumulant beaucoup de déductions dans différents domaines, le score brut global peut déjà être sous le seuil du plafond — le delta n'est jamais ajouté, le score du domaine cible n'est pas plafonné, et la barre d'affichage montre la valeur pré-plafond (ex. 6/10 au lieu de 3/10 pour le pare-feu quand UFW est inactif).

Correction : après accumulation des déductions par domaine depuis le breakdown, `compute_domain_scores()` lit maintenant `engine.cap_info` et, si sa clé correspond à un domaine, applique directement le plafond sur le total de déductions de ce domaine. Le fix est idempotent (si le delta était déjà dans le breakdown, le score du domaine est déjà égal au plafond, et la condition `raw_domain > cap.maximum` est fausse).

Trouvé en exécutant l'outil sur une VM Ubuntu 26.04 avec UFW inactif et plusieurs problèmes de durcissement : le détail du score affichait « Score plafonné à 3 (pare-feu inactif) » mais la barre de domaine montrait toujours 6/10.

### Fix 5 — Check de règle orpheline manquant les règles UFW sans protocole (`bob/checks/firewall.py`)

`_check_orphan_rules()` utilisait `_PORT_PROTO_RE` (`\d{1,5}/(?:tcp|udp)`) pour analyser le champ « To » des règles UFW. Une règle sans protocole explicite (ex. `57621 ALLOW IN 192.168.1.0/24`) ne matchait pas et était silencieusement ignorée avec le commentaire erroné « open-any rules ». UFW applique les règles port-sans-protocole aux deux protocoles (TCP et UDP).

Nouveau constante `_PORT_BARE_RE` gère le cas de repli : si ni `port/tcp` ni `port/udp` n'est dans les ports en écoute, la règle est signalée comme orpheline. Trouvé en exécutant l'outil sur une machine réelle où `57621` (Spotify Connect) n'était pas signalé alors que la règle jumelle `41681/tcp` l'était.

### Fix 6 — Locale SSH : commande dupliquée dans le bloc « Que faire ? » (`bob/locales/fr.json`, `bob/locales/en.json`)

`ssh.not_active_detail` contenait `"Activer avec : sudo systemctl enable --now ssh"`. Le champ `cmd` affichant déjà la commande séparément, le bloc « Que faire ? » la montrait deux fois. Corrigé : le `detail` fournit maintenant un contexte (« Le service est désactivé — activez-le si l'accès SSH est nécessaire. ») et la commande apparaît uniquement via `cmd`. Trouvé en testant l'outil sur Kali Linux où SSH est installé mais intentionnellement arrêté.

### Invariants scoring — nouvelles classes de test (`tests/test_scoring.py`, `tests/test_domain_scores.py`)

`TestScoringInvariants` ajouté aux deux fichiers — 12 nouveaux tests couvrant les propriétés devant tenir quel que soit l'input :

| Classe | Fichier | Invariants |
|--------|---------|------------|
| `TestScoringInvariants` | `test_scoring.py` | Score plancher = 0 · plafond = MAX · déductions monotones · plafond supérieur = no-op · override domaine dans la plage |
| `TestScoringInvariants` | `test_domain_scores.py` | Findings INFO n'activent pas le domaine · WARN/ALERT si · déduction seule active · moyenne globale ∈ [min, max] des actifs · tous scores dans [0, 10] · moyenne globale toujours dans [0, 10] |

### Tests

4261/4261 (+23 nouveaux, 2 mis à jour) :

| Fichier | Changement | Couverture |
|---------|------------|-----------|
| `tests/test_domain_scores.py` | +6 `TestEngineLevelDomainCap` | Plafond appliqué avec peu de déductions · plafond appliqué quand le score brut global est déjà sous seuil (delta absent du breakdown) · pas de sur-plafonnement si déjà au plafond · score ne dépasse jamais le plafond · pas de saignement vers d'autres domaines · tous scores dans la plage |
| `tests/test_firewall.py` | +3 `TestOrphanRules` | Règle bare-port signalée si rien en écoute · non signalée si TCP en écoute · non signalée si UDP en écoute |
| `tests/test_scoring.py` | +5 `TestScoringInvariants` | Plancher/plafond · déductions monotones · plafond no-op · override dans la plage |
| `tests/test_domain_scores.py` | +7 `TestScoringInvariants` | Activation INFO/WARN/ALERT · chemin déduction · bornes moyenne globale · scores dans la plage |
| `tests/test_manage_logs.py` | +2 `TestStatFallback` | Fallback `OSError` sur `.stat()` dans la boucle `cur_logs` → `(0, "?")` · idem boucle `extra_sections` |
| `tests/test_clamav.py` | renommé + mis à jour | `test_db_very_outdated_deducts_1` (était `_deducts_2`) · `test_worst_case` : 3 pts total (était 4) |

---

## [v0.2.1] — 02-05-2026

Hotfix défensif — 17 améliorations ciblées trouvées par audit dual-agent. Aucune nouvelle fonctionnalité, aucun changement de comportement. 4238/4238 tests inchangés.

### Correction de crash — mode texte `--manage-logs` (`bob/manage_logs.py`)

**Problème :** les appels `.stat()` sur les chemins de fichiers logs n'étaient pas protégés dans les boucles d'affichage mode texte. Si un fichier disparaissait entre le scan du répertoire et l'affichage, `--manage-logs` plantait avec `OSError`. Le mode curses avait déjà la protection `try/except OSError` correcte ; le mode texte non.

**Correction :** les deux boucles (`cur_logs` et `extra_sections`) enveloppent maintenant `.stat()` dans `try/except OSError` avec valeurs de repli `(size_kb=0, mtime="?")`, alignées sur l'implémentation curses.

### Resserrement des gestionnaires d'exceptions (8 emplacements)

Tous les `except Exception` remplacés par les exceptions spécifiques pouvant réellement être levées :

| Fichier | Fonction | Avant | Après |
|---------|----------|-------|-------|
| `bob/cis_refs.py` | `_load()` | `Exception` | `(OSError, json.JSONDecodeError)` |
| `bob/manage_logs.py` | `_get_extra_dirs()` | `Exception` | `(json.JSONDecodeError, ValueError, TypeError)` |
| `bob/manage_logs.py` | repli curses | `Exception` | `(curses.error, OSError)` |
| `bob/explain.py` | repli curses | `Exception` | `(curses.error, OSError)` |
| `bob/cron.py` | `run_install_cron()` | `Exception` | `(_curses.error, OSError)` |
| `bob/cron.py` | `run_manage_cron()` | `Exception` | `(_curses.error, OSError)` |
| `bob/checks/ssh.py` | `_rsa_bits_from_blob()` | `Exception` | `(struct.error, ValueError)` |
| `bob/checks/ssh.py` | `_has_passphrase()` | `Exception` | `(binascii.Error, ValueError)` |

### Regex déplacées en module-level (3 fichiers)

Patterns recompilés à chaque appel de fonction, maintenant constantes module :

| Fichier | Constantes |
|---------|-----------|
| `bob/checks/firewall.py` | `_OPEN_ANY_RE`, `_ALLOW_IN_RE`, `_PORT_PROTO_RE` |
| `bob/checks/cron_audit.py` | `_PATH_RE` |
| `bob/checks/firmware.py` | `_FLAT_SKIP_RE` |

### Qualité du code (3 corrections)

- **Regex email dédupliqué** (`bob/cron.py`) — `_EMAIL_RE` était défini identiquement dans 3 fonctions locales ; maintenant une seule constante module.
- **Helper `_resolve_path()` extrait** (`bob/manage_logs.py`) — `Path(raw).expanduser().resolve() if raw else default` était dupliqué à deux endroits.
- **Accès direct aux attributs dans `domain_scores.py`** — `getattr(engine, "findings", [])` / `getattr(deduction, "key", None)` etc. remplacés par accès direct. `ScoreEngine` initialise toujours ces attributs.

### Observabilité (2 corrections)

- **`recurrence.py`** — `except … pass` remplacé par `_log.debug()` pour que les échecs de chargement soient visibles en mode `--debug`.
- **`__main__.py`** — les échecs webhook émettent maintenant `_log.warning()` en plus de l'affichage stderr.

### Tests

4238/4238 (inchangés — aucun nouveau test ; aucun changement de comportement introduit)

---

## [v0.2.0] — 01-05-2026

Cinq améliorations : refonte du scoring, détection MTA pour le cron, correction du faux positif kernel, correction de la dominance IoT dans les logs, et bannière ASCII orange.

### Refonte du scoring (`bob/scoring.py`, `bob/domain_scores.py`)

**Problème :** le score global était la somme brute de toutes les déductions depuis 10. Huit problèmes mineurs de durcissement sur une machine par ailleurs bien configurée (SSH 10/10, pare-feu 10/10, mises à jour 10/10) pouvaient produire 2/10 CRITIQUE — un score ne reflétant pas la posture réelle.

Deux corrections ciblées :

- **Plafond par outil** — `rootkit`, `clamav` et `file_integrity` contribuent au maximum 1 point de déduction à leur domaine, quel que soit le nombre de findings individuels. Élimine la double pénalité « base rkhunter obsolète + pas de scan enregistré = −2 ».
- **Score global = moyenne des scores de domaine actifs** — le score global est désormais la moyenne arrondie de tous les scores de domaine pour lesquels au moins un finding existe (services non installés exclus). Un domaine Durcissement dégradé ne fait plus s'effondrer le score global quand SSH, pare-feu et mises à jour sont à 10/10.

**Effet sur le cas de référence Debian 13 :** 8 déductions → était 2/10 CRITIQUE, reflète maintenant la plage réelle de 6 à 9/10 selon les domaines actifs.

Nouvelle API : `ScoreEngine.set_global_score()`, `compute_global_from_domains()`, `apply_domain_score_override()`.

### Détection MTA cron (`bob/cron.py`)

**Problème :** l'assistant cron avertissait `'mail' non disponible — installez mailutils` quand `mail` était absent, mais l'envoi réel utilise `sendmail`, pas `mail`. Le conseil était incorrect et incomplet.

Nouveau helper `_detect_mta()` :
- Vérifie `sendmail` (le binaire réellement utilisé pour la livraison)
- Identifie le fournisseur : Postfix, Exim, msmtp, ssmtp
- Affiche `✔ Transport mail : Postfix` quand disponible
- Affiche des instructions d'installation claires en cas d'absence : `sudo apt install postfix` (MTA local) ou `sudo apt install msmtp-mta` (relais via Gmail/SMTP)

### Correction faux positif kernel `-unsigned` (`bob/checks/kernel_modules.py`)

**Problème :** sur Debian avec Secure Boot activé, `linux-image-X-amd64` (signé) et `linux-image-X-amd64-unsigned` sont tous deux installés. Le système démarre correctement le noyau signé, mais BOB signalait `-unsigned` comme « plus récent installé » et avertissait « redémarrage requis ».

Nouveau helper `_strip_unsigned()` : le suffixe `-unsigned` est retiré avant la comparaison de versions. Exécuter le noyau signé alors que seule la variante unsigned de la même version est également installée n'est plus signalé.

### Dominance IoT dans les logs : WARN −1 pt (`bob/checks/logs.py`)

**Problème :** quand une seule IP privée représentait ≥ 70 % du trafic UFW bloqué (≥ 50 entrées), BOB émettait un finding INFO sans déduction de score. La fonctionnalité était documentée comme WARN −1 pt mais l'implémentation utilisait `result.info()` sans appel à `add_deduction()`.

**Correction :** `result.info()` remplacé par `result.warn()` + `result.add_deduction(points=1, key="logs.local_dominance")`. Nouvelle clé de localisation `deduction.local_dominance` ajoutée dans `en.json` et `fr.json`. Trois tests existants dans `tests/test_logs.py` corrigés pour vérifier le niveau WARN et la déduction d'1 point (total inchangé).

### Bannière ASCII orange (`bob/output.py`)

L'art ASCII `BOB` dans la bannière terminal est maintenant affiché en orange bold (`\033[1;38;5;208m`). Les caractères de bordure restent en bleu.

### Tests

4238/4238 (3 tests corrigés dans `tests/test_logs.py` — dominance IoT : INFO→WARN + vérification déduction ; total inchangé)

| Fichier | Nouveaux tests | Couverture |
|---------|----------------|-----------|
| `tests/test_kernel_modules.py` | +6 | Helper `_strip_unsigned` · variantes Debian signé/non-signé · vrai redémarrage toujours détecté |
| `tests/test_cron.py` | +6 | `_detect_mta` — sans sendmail, Postfix, Exim, msmtp, ssmtp, inconnu |
| `tests/test_scoring.py` | +6 | `set_global_score` — override, clamp, niveau, score brut inchangé |
| `tests/test_domain_scores.py` | +14 | Plafonds (rootkit/clamav/file_integrity) · `compute_global_from_domains` · `apply_domain_score_override` · scénario Debian 13 |
| `tests/test_logs.py` | 0 (+3 corrigés) | Dominance IoT : niveau WARN · déduction 1 pt · sous le seuil inchangé |

---

## [v0.1.1] — 29-04-2026

Trois corrections ciblées trouvées lors des premiers lancements sur Ubuntu 26.04 LTS et Debian 13.

### Corrections

- **Parser fwupd format arbre** (`bob/checks/firmware.py`) — fwupd 1.9+ (Ubuntu 26.04+) a changé son format de sortie vers une structure en arbre avec les caractères `├─`, `└─`, `│`. L'ancien parser capturait ces caractères comme noms d'appareils, produisant une sortie corrompue (`│, ├─UEFI CA: (+7)`). Les noms d'appareils sont désormais extraits uniquement depuis les lignes `├─`/`└─`.
- **Message d'erreur `--install-completion`** (`bob/__main__.py`) — les utilisateurs qui lançaient `sudo bob --install-completion` obtenaient `sudo: 'bob': command not found` car sudo utilise un PATH restreint qui n'inclut pas les binaires pipx. Le message d'erreur avertit maintenant explicitement que `sudo bob` ne fonctionnera pas et invite à copier-coller la commande exacte avec le chemin complet.
- **En-tête de colonne du panorama des services** (`bob/locales/en.json`, `bob/locales/fr.json`) — renommé `UFW` → `SCOPE` (EN) / `PORTÉE` (FR). La colonne indique si un service a une exposition internet, pas si une règle UFW active le couvre — l'ancien label créait une fausse impression.

### Tests

4206/4206 (+4 tests de régression pour le parser fwupd format arbre dans `tests/test_firmware.py`)

---

## [v0.1.0] — 26-04-2026

Version initiale de **BOB — Bodyguard Of Bits**.

Auditeur de durcissement Linux avec mapping des benchmarks CIS. S'exécute en root, ne nécessite ni agent ni daemon.

### Vérifications de sécurité

46 vérifications réparties en 9 domaines :

- **Pare-feu** — audit des règles UFW, audit iptables/nftables (quand UFW est inactif), cohérence IPv6, analyse de la pile pare-feu, analyse d'exposition des ports
- **SSH** — 12+ paramètres de configuration (PermitRootLogin, PasswordAuthentication, qualité des clés, etc.)
- **Durcissement noyau** — 20+ paramètres sysctl ; audit des modules noyau ; Secure Boot ; firmware/microcode
- **Services** — 32 services connus avec classification du risque ; audit de l'état des services ; détection du contournement pare-feu Docker
- **Permissions fichiers** — audit SUID/SGID ; fichiers sensibles ; sudoers
- **Comptes utilisateurs** — comptes expirés ; politique de mots de passe ; login.defs ; PAM
- **Système** — mises à jour apt ; unattended-upgrades ; niveau de journalisation UFW ; rotation des logs ; analyse auth.log ; NTP ; Fail2ban ; scan rootkit ; auditd ; intégrité des fichiers (AIDE/Tripwire) ; ClamAV ; AppArmor/SELinux ; backup ; santé disque (SMART) ; mémoire/swap ; expiration certificats TLS/SSL ; timers systemd ; applications desktop ; Samba ; tâches cron ; DDNS
- **Réseau** — contexte IP publique ; détection du type de réseau (serveur/LAN/VPN) ; GeoIP optionnel
- **Docker** — configuration du daemon ; conteneurs privilégiés ; montages hôte

### Mapping des benchmarks CIS

133 entrées : 99 CIS Ubuntu 22.04 · 4 CIS Docker · 34 bonnes pratiques.
Chaque résultat avec un code CIS formel affiche `[CIS:X.Y.Z]` en ligne. Référence complète en mode `--verbose`.
`--explain CLÉ` affiche POURQUOI le résultat est important, COMMENT le corriger, et sa référence CIS.

### Formats de sortie

Terminal (coloré) · JSON · CSV · Markdown · HTML

### Profils d'audit

`server` · `workstation` · `desktop` · `docker` — ajustez la sévérité et ignorez les vérifications non pertinentes selon l'environnement.

### Automatisation

- **Cron** — assistant `--install-cron` ; TUI `--manage-cron` ; jobs nommés dans `/etc/cron.d/bob-{nom}`
- **Webhooks** — JSON générique + Slack (détecté automatiquement par l'URL)
- **Historique des scores** — tendance sparkline sur plusieurs exécutions (`--history`)
- **Scores par domaine** — scores 0–10 par domaine (firewall · SSH · hardening · updates · file_perms)
- **Mode diff** — `--diff` affiche uniquement les changements depuis la dernière baseline
- **Mode watch** — `--watch[=N]` relance toutes les N secondes

### CLI

```
sudo bob [OPTIONS]
bob --explain [CLÉ]   # sans sudo
```

Options clés : `--verbose` · `-d` (français) · `--offline` · `--fix` · `--apply` · `--check=LISTE` · `--skip=LISTE`
`--output-dir` · `--format` · `--target N` · `--min-level NIVEAU`

Complétion bash : `sudo bob --install-completion`

### i18n

Anglais et français (`--french` / `-d`).

### Installation

```
pipx install bodyguard-of-bits
sudo bob
```
