*[Read in English](CHANGELOG_FULL.md)* · *[TL;DR](../CHANGELOG_FR.md)*

# BOB — Bodyguard Of Bits — Journal des modifications

Toutes les modifications notables du projet sont documentées ici.

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
