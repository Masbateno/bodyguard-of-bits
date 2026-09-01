*[Read in English](README_DEV.md)*

# BOB — Documentation développeur

Ce document s'adresse aux personnes qui souhaitent contribuer au projet, ajouter un service, ajouter une langue, ou comprendre l'architecture interne.

---

## Table des matières

1. [Architecture](#architecture)
2. [Structure du projet](#structure-du-projet)
3. [Lancer les tests](#lancer-les-tests)
4. [Ajouter un service](#ajouter-un-service)
5. [Ajouter une langue](#ajouter-une-langue)
6. [Conventions de code](#conventions-de-code)
7. [Flux d'exécution](#flux-dexécution)
8. [Système de scoring](#système-de-scoring)
9. [Internationalisation](#internationalisation)

---

## Architecture

Le projet est structuré autour d'un principe central : **séparer la collecte de données de la logique métier**.

Chaque module de vérification suit le même pattern en deux étapes :

```
SystemSnapshot.from_system()   →   données brutes du système (subprocess)
check_xxx(snapshot, t)         →   logique pure, testable sans appels système
```

Cette séparation permet de tester toute la logique métier en instanciant directement des snapshots dans les tests, sans mock ni appels système réels.

### Modules principaux

| Module | Rôle |
|---|---|
| `__main__.py` | Orchestrateur — parsing des arguments, collecte des snapshots, appelle `run_checks()`, affiche le résumé (~401 lignes) |
| `runner.py` | Moteur d'exécution de l'audit — `run_checks()` avec closure `_sec` (38 sections filtrables + 10 always-on), `_section_enabled()` (~845 lignes) |
| `cli.py` | Parsing des arguments — retourne un `AuditConfig` dataclass |
| `config.py` | Configuration utilisateur — `UserConfig`, `EmailStore` |
| `display.py` | Helpers d'affichage terminal — `display_result()`, `print_audit_summary()`, etc. |
| `fixes.py` | Interface mode fix — interactif et auto-fix (`-f`/`-y`) |
| `i18n.py` | Internationalisation — `t("clé.sous_clé")` avec notation pointée |
| `manage_logs.py` | Interface `--manage-logs` — `run_manage_logs()`, `get_or_prompt_log_dir()` |
| `output.py` | Primitives terminal bas niveau — `print_ok/warn/alert/info/section/banner` |
| `panorama.py` | Constructeur du tableau panorama services — `build_panorama_rows()` |
| `registry.py` | Registre des services — charge `services.json`, expose `ServiceRegistry` |
| `report.py` | Fichier rapport — `AuditReport`, `NullReport`, écrit avec flush immédiat |
| `report_markdown.py` | Rapport markdown/HTML pour email — `MarkdownReport`, `send_html_email()` |
| `scoring.py` | Moteur de score — `ScoreEngine`, `CheckResult`, `Finding`, `Deduction` |
| `sysinfo.py` | Info système — `collect_system_info()`, `detect_network_context()`, `get_user_home()` |
| `compare.py` | Rapport comparatif — `AuditBaseline` (avec `finding_keys`), `AuditDelta` (avec `new_finding_keys`/`resolved_finding_keys`), `build_baseline()`, `save_baseline()`, `load_baseline()`, `compute_delta()`, `display_delta()` |
| `plugin_checks.py` | Chargeur de plugins — `PluginCheck`, `load_plugin_checks()`, sanitisation ANSI |
| `explain.py` | `--explain KEY` — `normalize_key()`, `run_explain()`, 169 clés canoniques dans 45 préfixes, variantes par profil (70 clés × 3 profils), lookup référence CIS via `cis_refs.py` |
| `cis_refs.py` | Lookup référence CIS — `get_cis_ref(key)`, `get_cis_code(key)`, `_load()` avec `lru_cache` ; données dans `data/cis_refs.json` (174 entrées : 107 CIS formels, 60 best-practice, 7 Docker) |
| `domain_scores.py` | Sous-scores par domaine — `compute_domain_scores()`, `render_domain_scores()`, attribution 7 domaines (`backup` → `disk`) |
| `webhook.py` | Envoi webhook — `build_generic_payload()`, `build_slack_payload()`, `send_webhook()`, auto-détection format |
| `correlation.py` | Moteur de corrélation — `CorrelationRule` (frozensets all_of/any_of), `CorrelatedFinding`, `run_correlations()`, 6 règles de risque composé intégrées |
| `exposure.py` | Analyse d'exposition des ports — regroupe par portée d'interface et niveau de risque ; allowlist fw_policy |
| `recurrence.py` | Suivi findings récurrents — `load_recurrence()`, `save_recurrence()`, `update_recurrence()` ; compteurs consécutifs dans `~/.config/bob/recurrence.json` |

### Module cron

| Module | Rôle |
|---|---|
| `cron.py` | Gestion cron — `CronEntry`, `list_installed_crons()`, `build_script_content()`, logique wizard planification (`run_install_cron()` / `run_manage_cron()` dispatchers — flux texte brut + dispatch curses en import paresseux) |
| `tui/cron.py` | TUI curses pour l'installation et la gestion cron — `_WizardEntry`, `_draw()`, `_read_key()`, `_run_install_cron_curses()`, `_run_manage_cron_curses()`. Vit sous `bob.tui` afin que le reste de `bob.*` reste importable sur les systèmes sans curses (extraction v0.4.1). |
| `_tty.py` | Lecteur ligne mode raw — `read_line(prompt) → str \| None` ; Échap retourne `None` ; repli `input()` en non-TTY |

### Modules de vérification (`checks/`)

| Module | Ce qu'il vérifie |
|---|---|
| `firewall.py` | Statut UFW, politique par défaut, cohérence IPv6 ; `check_rules()` pour la détection doublons/wildcards |
| `firewall_stack.py` | Contournement iptables brut, règles nftables parallèles, détection ip_forward |
| `iptables_nftables.py` | Audit iptables/nftables quand UFW inactif — politique INPUT/FORWARD, conntrack, détection backend (iptables-legacy vs nftables) |
| `ipv6.py` | Cohérence ports IPv6 / règles UFW v6 ; champ `has_global_ipv6` ; link-local/ULA uniquement → INFO (pas WARN) |
| `network_context.py` | Tableau d'interfaces réseau, connexions TCP établies, ports sensibles distants |
| `services.py` | Services réseau installés, état systemd, exposition UFW |
| `services_state.py` | État des services : services de sécurité activés au boot mais inactifs |
| `ports.py` | Ports en écoute via `ss`, classification, déduplication |
| `logs.py` | Logs UFW — tentatives bloquées, bruteforce, top IPs/ports |
| `log_rotation.py` | Rotation des logs : présence config logrotate, persistance journald, SystemMaxUse, rsyslog distant |
| `auth_log.py` | Analyse log de connexions SSH : connexions réussies, IPs sources, anomalies dans auth.log/journald |
| `ddns.py` | Clients DDNS actifs (ddclient), domaine configuré, ports ouverts croisés |
| `docker.py` | Détection install Docker, contournement iptables via chaîne DOCKER, exposition ports conteneurs |
| `docker_audit.py` | Durcissement daemon.json : conteneurs privilégiés, host network/pid/ipc, montages volume sensibles, no-new-privileges |
| `virtualization.py` | Hyperviseurs actifs (libvirt/KVM, VirtualBox, VMware, LXD/LXC) et paquets Snap réseau |
| `samba.py` | Audit sécurité Samba : SMBv1 désactivé, rejet null-password, signing serveur, `map to guest`, `bind interfaces only` |
| `smtp.py` | Exposition serveur SMTP : détection MTA (postfix/exim/sendmail), liaison localhost-only, risque open-relay |
| `hardening.py` | Durcissement système (sysctl) : rp_filter, send_redirects, accept_redirects, syncookies, accept_source_route, log_martians, protection hardlink/symlink |
| `kernel_hardening.py` | Durcissement noyau (sysctl) : ASLR, ptrace_scope, kptr_restrict, dmesg_restrict, suid_dumpable |
| `kernel_modules.py` | Modules noyau risqués (cramfs, hfs, dccp, sctp, rds, tipc, usb_storage) + disponibilité mise à jour noyau apt + listing noyaux installés (filtré sur état dpkg `ii` depuis v0.4.6) |
| `mac_policy.py` | Politique MAC (AppArmor / SELinux) : état framework, comptes de profils (enforce/complain/loaded), détection 0-profile |
| `updates.py` | État des mises à jour système : paquets apt sécurité/réguliers en attente (via `apt-get -s dist-upgrade`), détection cache obsolète, cross-check `apt list --upgradable`, détection unattended-upgrades |
| `ssh.py` | Audit sécurité SSH : directives sshd_config, qualité clés hôte, permissions clés user, authorized_keys, known_hosts |
| `file_perms.py` | Permissions fichiers sensibles : /etc/passwd, /etc/shadow, sudoers, clés hôte SSH |
| `suid_audit.py` | Audit binaires SUID/SGID avec whitelist (`config.conf`), scan targeted-roots pour la performance |
| `user_accounts.py` | Audit comptes utilisateurs : UID 0 non-root, mots de passe vides, comptes expirés |
| `password_policy.py` | Politique mots de passe : module PAM pam_pwquality / pam_cracklib, PASS_MAX_DAYS, login.defs |
| `umask.py` | Umask système : /etc/profile, /etc/bash.bashrc, /etc/login.defs, /etc/pam.d/common-session |
| `cron_audit.py` | Sécurité cron : pipe-to-shell, scripts world-writable, validateur de range |
| `disk.py` | Santé disques : SMART (smartctl), attributs critiques, utilisation partitions ; support NVMe ; skip si tous les disques sont virtuels |
| `backup.py` | Détection solution de sauvegarde : borgmatic / borg / restic / timeshift / duplicati / rclone, actif vs installé-seulement |
| `memory.py` | Mémoire & swap : détection usure SSD, swap injustifié (swap > 0 alors que RAM libre), swappiness |
| `desktop_apps.py` | Détection applications de bureau : applis GUI connues en cours d'exécution (Brave, kDrive, VSCode, ExpressVPN…) |
| `ntp.py` | Synchronisation NTP : systemd-timesyncd/chronyd/ntpd actif et synchronisé |
| `auditd.py` | Linux Audit Framework : installation, état service, règles chargées, surveillance fichiers sensibles |
| `secure_boot.py` | Secure Boot : état UEFI via mokutil/efivars/bootctl ; scoring adapté au profil |
| `fail2ban.py` | Prévention intrusion Fail2ban : état service, jails actifs, détection jail SSH |
| `clamav.py` | Antivirus ClamAV : installation, ancienneté BDD freshclam, date dernier scan |
| `file_integrity.py` | Intégrité des fichiers : installation AIDE/Tripwire, existence BDD, récence du dernier check |
| `rootkit.py` | Scan rootkit & intégrité : installation rkhunter/chkrootkit, fraîcheur BDD, date dernier scan |
| `ssl_certs.py` | Expiration certificats TLS/SSL : Let's Encrypt, `/etc/ssl/private` (snakeoil filtré), configs nginx/apache2/postfix |
| `systemd_timers.py` | Sécurité timers systemd : pipe-to-shell dans ExecStart, scripts world-writable, timers root utilisateur |
| `firmware.py` | Firmware & microcode : mises à jour fwupdmgr en attente, paquet microcode CPU via dpkg |
| `systemd_hardening.py` | **v0.13.0** — score d'exposition `systemd-analyze security` des services *en cours d'exécution* ; INFO-only, aucune déduction (la plupart des units sont livrées non durcies par défaut) |
| `container_security.py` | **v0.13.0** — posture du conteneur lue depuis `/proc` (CapBnd, mode seccomp, uid_map, rootfs inscriptible) ; section entièrement supprimée hors conteneur via `skip_if` ; INFO-only |
| `socket_units.py` | **v0.13.1** — units `.socket` systemd orphelines / en échec, à l'intersection systemd × sockets en écoute ; un `Triggers=` vide n'est jamais signalé, un service backing simplement inactif est sain ; INFO-only |
| `cloud_context.py` | **v0.13.1** — exposition cloud côté hôte (IMDS joignable on-link, user-data lisible par tous) ; détection conservatrice (provider DMI, ou cloud-init + route IMDS on-link) ; supprimée hors cloud, aucune API cloud ; INFO-only |

---

## Structure du projet

```
bob/
├── __init__.py
├── __main__.py          # Orchestrateur (~410 lignes — coordination pure)
├── _paths.py            # Résolution des chemins de données
├── _tty.py              # read_line() — lecteur de ligne mode raw avec Esc-pour-annuler, repli input()
├── breakdown.py         # Moteur de décomposition de score — trace per-deduction complète pour --breakdown / -B
├── cis_refs.py          # Lookup référence CIS — get_cis_ref(), get_cis_code() avec lru_cache
├── cli.py               # AuditConfig + parse_args()
├── compare.py           # AuditBaseline (finding_keys) + AuditDelta (new/resolved keys) + rapport comparatif
├── completion.py        # Installeur d'autocomplétion bash — `bob --install-completion`
├── config.py            # UserConfig, EmailStore
├── correlation.py       # CorrelationRule + run_correlations() — 6 règles de risque composé
├── cron.py              # CronEntry, logique wizard planification, build_script_content()
├── csv_output.py        # Formatter sortie CSV (--format csv)
├── display.py           # Helpers affichage terminal (display_result, print_audit_summary…)
├── domain_scores.py     # compute_domain_scores(), render_domain_scores() — attribution backup→disk
├── explain.py           # run_explain(), normalize_key(), EXPLAIN_KEYS — 169 clés dans 45 préfixes
├── exposure.py          # Regroupement exposition ports — portée d'interface + niveau de risque
├── fixes.py             # Interface mode fix (interactif + auto-fix)
├── formatter.py         # bob.formatter — rendu indépendant de la locale via Finding.template_vars (v0.4.1)
├── history.py           # Suivi historique de score — affichage sparkline pour --history
├── html_output.py       # build_html_output() — export HTML autonome (--html)
├── i18n.py              # t(key) avec notation pointée
├── ignore.py            # Liste d'ignore persistante par finding-key (~/.config/bob/ignore.yml)
├── json_output.py       # Formatter sortie JSON (--json / --json-full) avec schema_version=1
├── manage_logs.py       # Interface --manage-logs, get_or_prompt_log_dir()
├── markdown_output.py   # Formatter sortie Markdown (--format markdown)
├── output.py            # Primitives terminal bas niveau
├── panorama.py          # build_panorama_rows()
├── plugin_checks.py     # PluginCheck + load_plugin_checks()
├── profiles.py          # Chargeur de profil d'audit (server/workstation/desktop/docker + profils utilisateur)
├── recurrence.py        # Suivi findings récurrents — compteurs consécutifs
├── registry.py          # ServiceRegistry.load()
├── report.py            # AuditReport + NullReport
├── report_markdown.py   # MarkdownReport, email HTML
├── runner.py            # Moteur d'exécution d'audit — run_checks() avec closure _sec (38 filtrables + 10 always-on)
├── scoring.py           # ScoreEngine, CheckResult, Finding, Deduction
├── sysinfo.py           # collect_system_info(), detect_network_context(), get_user_home()
├── watch.py             # Mode --watch=N — relance l'audit toutes les N secondes
├── webhook.py           # build_generic_payload(), build_slack_payload(), send_webhook()
├── tui/
│   ├── __init__.py      # bob.tui — sous-package curses optionnel (v0.4.1)
│   └── cron.py          # TUI curses pour --install-cron / --manage-cron
├── checks/
│   ├── __init__.py
│   ├── _run.py             # Helper subprocess _run() partagé + env locale C,
│   │                       #   run_result() — sortie ET code de retour, pour
│   │                       #   les appelants qui ne doivent pas lire « n'a pas
│   │                       #   pu tourner » comme « rien trouvé » (v0.15.2),
│   │                       #   unit_active_state() — l'état d'une unité, ou
│   │                       #   None si systemd n'a pas répondu (v0.15.2),
│   │                       #   path_exists() — Path.exists() relève EACCES ;
│   │                       #   un seul appel nu a perdu un audit (v0.15.2),
│   │                       #   join_continuations(), strip_unit_glyph(),
│   │                       #   pipes_into_shell() — une seule copie par règle
│   ├── _ufw.py             # Grammaire `ufw status numbered`, partagée par ports,
│   │                       #   services, ipv6, ddns et firewall (v0.15.1)
│   ├── firewall.py         # FirewallStatus + check_firewall() + check_rules()
│   ├── firewall_stack.py   # FirewallStackSnapshot + check_firewall_stack()
│   ├── iptables_nftables.py # IptablesNftablesSnapshot + check_iptables_nftables() — audit pare-feu brut
│   ├── ipv6.py             # IPv6Snapshot + check_ipv6()
│   ├── network_context.py  # NetworkContextSnapshot + check_network_context()
│   ├── services.py         # ServiceSnapshot + check_services()
│   ├── services_state.py   # ServicesStateSnapshot + check_services_state()
│   ├── ports.py            # PortsSnapshot + check_ports()
│   ├── logs.py             # LogsSnapshot + check_logs()
│   ├── log_rotation.py     # LogRotationSnapshot + check_log_rotation()
│   ├── auth_log.py         # AuthLogSnapshot + check_auth_log() — analyse log de connexions SSH
│   ├── ddns.py             # DdnsSnapshot + check_ddns()
│   ├── docker.py           # DockerSnapshot + check_docker()
│   ├── docker_audit.py     # DockerAuditSnapshot + check_docker_audit() — durcissement daemon + conteneurs
│   ├── virtualization.py   # VirtSnapshot + check_virtualization()
│   ├── samba.py            # SambaSnapshot + check_samba() — SMBv1, signing, map-to-guest
│   ├── smtp.py             # SmtpSnapshot + check_smtp() — exposition MTA
│   ├── hardening.py        # HardeningSnapshot + check_hardening() — sysctl net.* / fs.*
│   ├── kernel_hardening.py # KernelHardeningSnapshot + check_kernel_hardening() — sysctl kernel.*
│   ├── kernel_modules.py   # KernelModulesSnapshot + check_kernel_modules() — modules risqués + mise à jour noyau apt
│   ├── mac_policy.py       # MacPolicySnapshot + check_mac_policy() — AppArmor / SELinux
│   ├── updates.py          # UpdatesSnapshot + check_updates() — sémantique dist-upgrade + cache obsolète
│   ├── ssh.py              # SshSnapshot + check_ssh()
│   ├── file_perms.py       # FilePermsSnapshot + check_file_perms()
│   ├── suid_audit.py       # SuidSnapshot + check_suid_audit() — SUID/SGID avec whitelist
│   ├── user_accounts.py    # UserAccountsSnapshot + check_user_accounts()
│   ├── password_policy.py  # PasswordPolicySnapshot + check_password_policy()
│   ├── umask.py            # UmaskSnapshot + check_umask() — login.defs, common-session
│   ├── cron_audit.py       # CronAuditSnapshot + check_cron_audit()
│   ├── disk.py             # DiskSnapshot + check_disk() — SMART, partitions, NVMe
│   ├── backup.py           # BackupSnapshot + check_backup() — détection borgmatic/restic/timeshift
│   ├── memory.py           # MemorySnapshot + check_memory() — usure SSD, swappiness
│   ├── desktop_apps.py     # DesktopAppsSnapshot + check_desktop_apps() — détection applis GUI
│   ├── ntp.py              # NtpSnapshot + check_ntp() — état synchronisation NTP
│   ├── auditd.py           # AuditdSnapshot + check_auditd() — Linux Audit Framework
│   ├── secure_boot.py      # SecureBootSnapshot + check_secure_boot() — état UEFI
│   ├── fail2ban.py         # Fail2banSnapshot + check_fail2ban() — service, jails, jail SSH
│   ├── clamav.py           # ClamAVSnapshot + check_clamav() — fraîcheur BDD, dernier scan
│   ├── file_integrity.py   # FileIntegritySnapshot + check_file_integrity() — AIDE/Tripwire
│   ├── rootkit.py          # RootkitSnapshot + check_rootkit() — rkhunter/chkrootkit
│   ├── ssl_certs.py        # SslCertsSnapshot + check_ssl_certs() — expiration certs
│   ├── systemd_timers.py   # SystemdTimersSnapshot + check_systemd_timers() — sécurité des timers
│   ├── firmware.py         # FirmwareSnapshot + check_firmware() — fwupd + microcode
│   ├── systemd_hardening.py    # ServiceHardeningSnapshot + check_service_hardening() (v0.13.0)
│   ├── container_security.py   # ContainerSecuritySnapshot + check_container_security() (v0.13.0)
│   ├── socket_units.py         # SocketUnitsSnapshot + check_socket_units() (v0.13.1)
│   └── cloud_context.py        # CloudContextSnapshot + check_cloud_context() (v0.13.1)
├── data/
│   ├── services.json            # Registre déclaratif des 38 services
│   ├── cis_refs.json            # Références CIS — 174 entrées {ref, code}
│   └── bob.bash-completion  # Script d'autocomplétion bash
└── locales/
    ├── en.json          # Clés de traduction anglais
    └── fr.json          # Clés de traduction français

tests/
├── helpers.py           # Utilitaires partagés : _t, levels, _has_finding, _get_finding, _deduction_keys…
├── test_check_rules.py
├── test_cli.py
├── test_compare.py
├── test_config.py
├── test_cron.py
├── test_ddns.py
├── test_degraded.py
├── test_docker.py
├── test_email_store_mgmt.py
├── test_firewall.py
├── test_firewall_stack.py
├── test_fixes.py
├── test_hardening.py
├── test_i18n.py
├── test_ipv6.py
├── test_logs.py
├── test_network_context.py
├── test_output.py
├── test_plugin_checks.py
├── test_ports.py
├── test_registry.py
├── test_report.py
├── test_scoring.py
├── test_services.py
├── test_sysinfo.py
├── test_virtualization.py
├── test_updates.py
├── test_explain.py
├── test_domain_scores.py
├── test_webhook.py
├── test_user_accounts.py
├── test_password_policy.py
├── test_display_explain_hint.py
├── test_disk.py
├── test_memory.py
├── test_desktop_apps.py
├── test_ntp.py
├── test_fail2ban.py
├── test_rootkit.py
├── test_exit_codes.py
├── test_ssl_certs.py
├── test_systemd_timers.py
├── test_firmware.py
├── test_html_output.py
├── test_correlation.py
├── test_exposure.py
├── test_recurrence.py
├── test_manage_logs.py
├── test_iptables_nftables.py
└── test_cis_refs.py

pyproject.toml           # Config de build (setuptools, installation pip/pipx)
README.md / README_FR.md           # Documentation utilisateur (EN/FR)
README_DEV.md / README_DEV_FR.md   # Ce fichier (EN/FR)
CHANGELOG_FULL.md / CHANGELOG_FULL_FR.md  # Historique complet des versions (EN/FR)
TESTING.md / TESTING_FR.md         # Plan de test manuel (EN/FR)
AUTOMATION.md / AUTOMATION_FR.md   # Guide d'automatisation (EN/FR)
```

---

## Lancer les tests

### Prérequis

```bash
python3 --version   # 3.10+ requis
```

Aucune dépendance PyPI — stdlib uniquement.

### Lancer tous les tests

```bash
cd bodyguard-of-bits
python3 -m pytest tests/ -v
```

### Lancer un module spécifique

```bash
python3 -m pytest tests/test_scoring.py -v
python3 -m pytest tests/test_logs.py -v
```

### Lancer sans pytest (stdlib uniquement)

Chaque fichier de test peut être lancé directement :

```bash
python3 -m unittest tests/test_firewall.py
```

### Résultats attendus

```
4500 passed in X.XXs
```

Les tests n'effectuent aucun appel système — tous les snapshots sont construits directement dans les tests. Ils peuvent être lancés sans `sudo` et sans UFW installé.

---

## Ajouter un service

Tout se passe dans `bob/data/services.json`. Aucune modification de code Python n'est nécessaire pour les services avec détection standard.

### Structure d'une entrée service

```json
{
  "id": "mon_service",
  "label": "Mon Service",
  "packages": ["mon-service"],
  "services": ["mon-service"],
  "ports": ["1234/tcp"],
  "risk": "medium",
  "config_key": "fixed",
  "detection": {
    "binary": [],
    "snap": [],
    "config_files": []
  }
}
```

### Champs obligatoires

| Champ | Type | Description |
|---|---|---|
| `id` | string | Identifiant unique, snake_case |
| `label` | string | Nom affiché à l'écran |
| `packages` | array | Noms de paquets dpkg à détecter |
| `services` | array | Noms de services systemd |
| `ports` | array | Ports par défaut — format `"numéro/proto"` |
| `risk` | string | `"critical"`, `"high"`, `"medium"`, `"low"` |
| `config_key` | string | `"fixed"` ou `"auto"` |
| `detection` | object | Méthodes de détection alternatives |

### Niveaux de risque

| Valeur | Signification | Effet |
|---|---|---|
| `critical` | Service très sensible | Contexte de risque affiché, déductions doublées en contexte public |
| `high` | Service sensible | Contexte de risque affiché, déductions doublées en contexte public |
| `medium` | Service standard | Pas de contexte de risque |
| `low` | Service interne | Pas de contexte de risque |

### Détection par binaire ou snap

Pour les services sans paquet dpkg standard :

```json
"detection": {
  "binary": ["/usr/local/bin/mon-service"],
  "snap": ["mon-service-snap"],
  "config_files": []
}
```

### Port auto-détecté depuis la config

Si le service peut écouter sur un port configurable, utiliser `"config_key": "auto"` et fournir le fichier de configuration :

```json
"config_key": "auto",
"detection": {
  "config_files": ["/etc/mon-service/mon-service.conf"]
}
```

Le module `services.py` tentera d'extraire le port depuis les patterns courants (`port = 1234`, `listen = 1234`, etc.).

### Ajouter le contexte de risque (services critical/high uniquement)

Pour les services `critical` ou `high`, ajouter les clés dans les deux fichiers de locale.

La clé est construite depuis le label : minuscules, espaces → `_`, `/` → `_`, `(` et `)` supprimés.

Exemple pour `"label": "Mon Service (daemon)"` → clé `mon_service_daemon` :

Dans `locales/en.json` :
```json
"service_risk": {
  "mon_service_daemon": {
    "level": "HIGH",
    "exposure": "Description of the exposure vector",
    "threat": "Description of the potential threat"
  }
}
```

Dans `locales/fr.json` :
```json
"service_risk": {
  "mon_service_daemon": {
    "level": "ÉLEVÉ",
    "exposure": "Description du vecteur d'exposition",
    "threat": "Description de la menace potentielle"
  }
}
```

### Vérifier la parité des clés

Après toute modification des locales :

```bash
python3 -c "
import json
def keys(d, p=''):
    k = set()
    for a,v in d.items():
        f = f'{p}.{a}' if p else a
        k |= keys(v,f) if isinstance(v,dict) else {f}
    return k
en = keys(json.load(open('bob/locales/en.json')))
fr = keys(json.load(open('bob/locales/fr.json')))
print(f'EN keys: {len(en)}')
print(f'FR keys: {len(fr)}')
missing = en - fr
print(f'Missing in FR: {missing if missing else \"none\"}')
"
```

Résultat attendu :
```
EN keys: 1401
FR keys: 1401
Missing in FR: none
```

---

## Ajouter une langue

### 1. Créer le fichier de locale

```bash
cp bob/locales/en.json bob/locales/de.json
```

### 2. Traduire toutes les valeurs

Le fichier contient exactement 2060 clés organisées en sections (vérifié par le test de stricte parité `bob/locales/en.json` vs `fr.json`). Traduire toutes les valeurs en conservant les placeholders `{variable}` intacts.

Exemple :
```json
"ports.listening_count": "{count} listening port(s) detected on this system"
```
devient :
```json
"ports.listening_count": "{count} lauschende(r) Port(s) auf diesem System erkannt"
```

### 3. Ajouter le flag CLI

Dans `bob/cli.py`, ajouter l'option dans `parse_args()` :

```python
elif arg in ("--german", "--deutsch"):
    config.lang = "de"
```

### 4. Vérifier la parité

```bash
python3 -c "
import json
def keys(d, p=''):
    k = set()
    for a,v in d.items():
        f = f'{p}.{a}' if p else a
        k |= keys(v,f) if isinstance(v,dict) else {f}
    return k
en = keys(json.load(open('bob/locales/en.json')))
de = keys(json.load(open('bob/locales/de.json')))
missing = en - de
print(f'Missing: {missing if missing else \"none\"}')
"
```

---

## Conventions de code

### Pattern snapshot / check

Chaque module de vérification suit strictement ce pattern :

```python
@dataclass
class XxxSnapshot:
    # Données brutes collectées du système
    field_a: str
    field_b: int

    @classmethod
    def from_system(cls) -> "XxxSnapshot":
        # Appels subprocess ici — UNIQUEMENT ici
        data = _run("command", "arg")
        return cls(field_a=data, field_b=0)


def check_xxx(snapshot: XxxSnapshot, t=None) -> CheckResult:
    # Logique pure — JAMAIS d'appels subprocess ici
    _t = t if t is not None else _identity_t
    result = CheckResult()
    # ...
    return result
```

**Règle absolue :** `check_xxx()` ne fait jamais appel à subprocess. Toute la collecte est dans `from_system()`.

**Depuis la v0.14.1 — trois règles qui découlent de la barrière d'isolation :**

1. **Enregistrer le collecteur, pas le snapshot.** `runner._sec` prend
   `XxxSnapshot.from_system` (un callable), jamais `XxxSnapshot.from_system()`
   (un objet déjà construit). Le collecteur est invoqué *à l'intérieur* de la
   barrière : une panne à cet endroit dégrade la section au lieu d'interrompre
   l'audit — et une section exclue par `--check` / `--skip` / le profil ne coûte
   rien. Passer un snapshot pré-construit déplace silencieusement la collecte
   hors de la barrière ; `tests/test_v0141_robustness.py` fait échouer le build
   si un site d'appel le fait. (`hardening_snapshot` est l'exception documentée
   — il alimente aussi `ChecksResult` pour le bloc sysctl de `--json-full`.)

2. **Lire les fichiers via `bob._atomic.read_text_capped()`**, pas `read_text()`.
   Il refuse tout ce qui n'est pas un fichier régulier (périphérique, FIFO,
   répertoire) et borne la lecture, et il déclare `errors="replace"` pour qu'un
   octet non-UTF-8 dans un fichier système dégrade au lieu de lever. Un
   `read_text()` nu dans un bloc `except OSError` est rejeté par un garde AST
   qui balaie tout le paquet.

3. **Ne pas assainir soi-même le texte des findings.** `Finding.__post_init__()`
   retire les séquences ANSI et les caractères de contrôle de `message` /
   `detail` / `note` (et de `cmd`, en préservant les sauts de ligne), au point
   unique par lequel passe chaque finding. Interpole directement les valeurs
   venues du système.

Un check qui lève n'est plus fatal, mais il n'est pas gratuit pour autant : la
section est rapportée comme un finding INFO `<section>.unavailable` et listée
dans le `degraded_sections` du JSON. Dégrader proprement dans le check reste
préférable à s'en remettre à la barrière.

### CheckResult

```python
result = CheckResult()

result.ok(message=_t("clé"))                          # ✔ finding
result.warn(message=_t("clé"), nature="improvement")  # ⚠ finding
result.alert(message=_t("clé"), nature="action",      # ✖ finding
             cmd="sudo ufw ...")
result.info(message=_t("clé"))                        # ℹ finding

result.add_deduction(
    reason=_t("clé"),
    points=2,
    context="local",   # ou "public"
)
```

### Natures des findings

| Nature | Signification | Bloc résumé |
|---|---|---|
| `"action"` | Correction requise | *Action requise* |
| `"improvement"` | Amélioration possible | *Améliorations possibles* |
| `"structural"` | Configuration normale mais notable | *Configuration normale* |
| `None` | Informatif pur | Non affiché dans le résumé |

### Fonction de traduction

Toujours passer `t` en paramètre avec fallback identity :

```python
def check_xxx(snapshot, t=None) -> CheckResult:
    _t = t if t is not None else _identity_t
```

Cela permet de tester sans initialiser i18n :

```python
result = check_firewall(make_status())          # clés brutes dans les messages
result = check_firewall(make_status(), t=my_t)  # traduction personnalisée
```

### Subprocess

Toujours via le helper `_run()` local à chaque module :

```python
def _run(*args: str) -> str:
    try:
        proc = subprocess.run(
            list(args), capture_output=True, text=True, timeout=10,
        )
        return proc.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""
```

Ne jamais laisser une exception subprocess remonter.

### Tests

Chaque module de vérification a son fichier de test correspondant. Les tests :

- Ne font aucun appel système
- Construisent les snapshots directement
- Testent la logique pure dans `check_xxx()`
- Testent les helpers de parsing séparément

Structure type :

```python
def make_snapshot(**overrides) -> XxxSnapshot:
    defaults = dict(field_a="default", field_b=0)
    defaults.update(overrides)
    return XxxSnapshot(**defaults)

def test_nominal_case():
    snap = make_snapshot(field_a="value")
    result = check_xxx(snap)
    assert "ok" in [f.level.value for f in result.findings]
```

---

## Flux d'exécution

```
main()
  │
  ├── parse_args()              → AuditConfig
  ├── i18n.init(lang)           → charge les locales
  ├── ServiceRegistry.load()    → charge services.json
  ├── UserConfig.load()         → charge config utilisateur
  ├── AuditReport.open() / .null()
  ├── ScoreEngine(profile=active_profile)
  │
  ├── CHECK 1 — Firewall
  │     FirewallStatus.from_system()
  │     check_firewall(status, t)
  │     engine.apply(result)
  │
  ├── CHECK 2 — Règles UFW
  │     check_rules(ufw_verbose, ufw_numbered, t)   ← checks/firewall.py
  │     engine.apply(result)
  │
  ├── CHECK 3 — Services réseau
  │     ServiceSnapshot.collect(registry)
  │     pour chaque service :
  │       check_services([snap], t)
  │       engine.apply(result)
  │
  ├── CHECK 4 — Ports en écoute
  │     PortsSnapshot.from_system()
  │     check_ports(snapshot, audited_ports, t)
  │     engine.apply(result)
  │
  ├── CHECK 5 — Logs UFW
  │     LogsSnapshot.from_system(log_days)
  │     check_logs(snapshot, audited_ports, t)
  │     engine.apply(result)
  │
  ├── CHECK 6 — DDNS
  │     DdnsSnapshot.from_system()
  │     check_ddns(snapshot, ufw_rules, t)
  │     engine.apply(result)
  │
  ├── CHECK 7 — Docker
  │     DockerSnapshot.from_system()
  │     check_docker(snapshot, t)
  │     engine.apply(result)
  │
  ├── engine.finalize()                    → calcule score final
  ├── print_audit_summary(engine, …)       ← display.py
  ├── build_risk_context_entries(…)        ← display.py
  └── report.close()
```

---

## Système de scoring

### Calcul du score

Le score démarre à 10/10. Chaque `Deduction` soustrait des points. Après l'exécution de toutes les vérifications, le score global est remplacé par la valeur moyennée par domaine.

```python
engine = ScoreEngine(profile=active_profile)   # v0.14.0 : l'engine porte le profil
engine.apply(check_result)              # applique les overrides du profil, puis findings + déductions
engine.cap(maximum=3, key="firewall.inactive")  # plafonne si pare-feu inactif
engine.finalize()                       # applique le plafond, clamp à [0, 10]
apply_domain_score_override(engine)     # score global = moyenne des domaines actifs
                                        # DOIT être appelé après finalize()

score = engine.score         # int 0–10 — domain-averaged si override défini
level = engine.level         # RiskLevel.LOW / MEDIUM / HIGH / CRITICAL
raw   = engine._raw_score    # score brut pré-override (débogage uniquement)
```

**Contrat orchestrateur :** `apply_domain_score_override(engine)` depuis `bob.domain_scores` doit être appelé après `engine.finalize()`. Avant cet appel, `engine.score` retourne le score brut basé sur les déductions. Ne pas appeler `engine.set_global_score()` directement.

**Ensemble des domaines actifs :** un domaine compte comme « actif » dans la moyenne globale dès qu'un check de ce domaine émet un finding `OK`, `WARN` ou `ALERT` (ou une déduction avec une clé). Les findings `INFO` seuls (observations purement consultatives) ne promeuvent pas un domaine à eux seuls — ils sont explicitement exclus pour que les domaines avec uniquement des notices informatives restent cachés. L'inclusion du `OK` est le fix v0.4.6 (Bug 2) : avant lui, un domaine qui passait clean après remédiation (seul `updates.ok` subsistant après `apt upgrade`) sortait du set actif et le score global *baissait* malgré un système strictement plus sécurisé.

**Pondération égale des domaines :** tous les domaines actifs contribuent également à la moyenne globale — il n'y a pas de pondération par domaine. Une machine où seul SSH est dégradé et tous les autres domaines sont à 10/10 bénéficie de la dilution ; une machine avec les sept domaines actifs accorde le même poids au pare-feu qu'à la santé du disque. C'est un choix de conception intentionnel maintenu à travers la v0.4.x.

**`ScoreCap.key` :** les plafonds portent un champ `key` propagé à leur déduction synthétique de breakdown, permettant l'attribution au domaine pour les déductions déclenchées par un plafond.

### Contexte réseau

Le contexte `"public"` (machine avec IP directement accessible sur internet) double les pénalités pour les services critiques exposés.

```python
result.add_deduction(reason="...", points=2, context="public")
```

### Niveaux de risque

| Score | Niveau |
|---|---|
| 8–10 | FAIBLE |
| 5–7 | MOYEN |
| 3–4 | ÉLEVÉ |
| 0–2 | CRITIQUE |

---

## Internationalisation

### Accès aux traductions

```python
from bob.i18n import t

# Clé simple
t("firewall.active")
# → "Le pare-feu UFW est actif"

# Clé avec variable
t("ports.listening_count", count=17)
# → "17 port(s) en écoute détecté(s) sur ce système"
```

### Clé manquante

Si une clé n'existe pas, `t()` retourne `"[clé.manquante]"` — jamais une exception. Cela facilite le développement incrémental.

### Localisation des fichiers de données

Les fichiers de locale et `services.json` sont lus depuis les répertoires `locales/` et `data/` relatifs au module Python (`Path(__file__).parent`). Cela fonctionne en développement comme avec pipx (qui inclut les fichiers de données dans l'environnement isolé).

`$BOB_SHARE` peut pointer vers un répertoire de données partagé (ex. `/usr/local/share/bob/`) pour les installs via paquet système. Si défini sur un répertoire absolu existant, il prend la priorité sur le chemin embarqué ; sinon BOB retombe sur les `locales/` et `data/` relatifs au paquet. La résolution est dans `bob/_paths.py` (strict — un chemin manquant, relatif ou non sûr est ignoré avec un warning). Non utilisé avec pipx.

```python
# bob/_paths.py — résolution du share-dir
share = os.environ.get("BOB_SHARE", "").strip()
if share:
    resolved = Path(share).resolve(strict=True)   # ignoré si manquant / non absolu
    # → resolved / "locales", resolved / "data"
```

> L'alias legacy `UFW_AUDIT_SHARE` a été déprécié en v0.5.4 et **supprimé** — utiliser `BOB_SHARE`.

---

## Variables d'environnement

| Variable | Effet |
|---|---|
| `BOB_SHARE` | Répertoire des données partagées (locales, services.json) — prioritaire sur le chemin embarqué si défini sur un répertoire absolu existant ; non utilisé avec pipx. (Legacy `UFW_AUDIT_SHARE` supprimé en v0.5.4.) |
| `SUDO_USER` | Utilisateur réel sous sudo — utilisé pour le chemin de config et le rapport |
| `NO_COLOR` | Désactive les couleurs ANSI (standard) |


---

© 2026 Cédric Clauzel
