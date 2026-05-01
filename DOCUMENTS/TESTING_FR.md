*[Read in English](TESTING.md)*

# BOB — Plan de test : règles UFW dangereuses

Tests de régression manuels utilisant des règles UFW délibérément dangereuses.
Chaque test vérifie que BOB détecte (et corrige) correctement une mauvaise configuration spécifique.

---

## Historique des tests unitaires

| Version | Tests | Notes |
|---------|-------|-------|
| v0.2.0  | 4238  | +32 nouveaux tests · 3 corrigés : `_strip_unsigned` · `_detect_mta` · `set_global_score` · plafonds par outil · dominance IoT WARN |
| v0.1.1  | 4206  | +4 tests de régression : parser fwupd 1.9+ format arbre (`├─`/`└─`) — bug trouvé sur Ubuntu 26.04 LTS |
| post-v0.1.0 | 4202 | +2 tests de régression : findings INFO non détectés en surface d'attaque (`ssh.not_installed`, `fail2ban.not_installed`) — bugs trouvés sur Ubuntu 26.04 LTS |
| v0.1.0  | 4200  | Version initiale — 65 fichiers de test ; 39 nouveaux tests dans `test_cis_refs.py` (mapping benchmarks CIS) ; couverture complète des 46 vérifications |

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
