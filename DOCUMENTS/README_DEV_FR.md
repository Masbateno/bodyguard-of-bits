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
| `runner.py` | Moteur d'exécution de l'audit — `run_checks()` avec closure `_sec` (29 sections), `_section_enabled()` (656 lignes) |
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
| `explain.py` | `--explain KEY` — `normalize_key()`, `run_explain()`, 112 clés canoniques dans 26 groupes, variantes par profil (17 clés × 3 profils), lookup référence CIS via `cis_refs.py` |
| `cis_refs.py` | Lookup référence CIS — `get_cis_ref(key)`, `get_cis_code(key)`, `_load()` avec `lru_cache` ; données dans `data/cis_refs.json` (133 entrées : 99 CIS formels, 34 best-practice, 4 Docker) |
| `domain_scores.py` | Sous-scores par domaine — `compute_domain_scores()`, `render_domain_scores()`, attribution 7 domaines (`backup` → `disk`) |
| `webhook.py` | Envoi webhook — `build_generic_payload()`, `build_slack_payload()`, `send_webhook()`, auto-détection format |
| `correlation.py` | Moteur de corrélation — `CorrelationRule` (frozensets all_of/any_of), `CorrelatedFinding`, `run_correlations()`, 5 règles de risque composé intégrées |
| `exposure.py` | Analyse d'exposition des ports — regroupe par portée d'interface et niveau de risque ; allowlist fw_policy |
| `recurrence.py` | Suivi findings récurrents — `load_recurrence()`, `save_recurrence()`, `update_recurrence()` ; compteurs consécutifs dans `~/.config/bob/recurrence.json` |

### Module cron

| Module | Rôle |
|---|---|
| `cron.py` | Gestion cron — `CronEntry`, `list_installed_crons()`, `build_script_content()`, logique wizard planification (`run_install_cron()` / `run_manage_cron()` dispatchers — flux texte brut + dispatch curses en import paresseux) |
| `cron_ui.py` | TUI curses pour l'installation et la gestion cron — `_WizardEntry`, `_draw()`, `_read_key()`, `_run_install_cron_curses()`, `_run_manage_cron_curses()` |
| `_tty.py` | Lecteur ligne mode raw — `read_line(prompt) → str \| None` ; Échap retourne `None` ; repli `input()` en non-TTY |

### Modules de vérification (`checks/`)

| Module | Ce qu'il vérifie |
|---|---|
| `firewall.py` | Statut UFW, politique par défaut, cohérence IPv6 ; `check_rules()` pour la détection doublons/wildcards |
| `services.py` | Services réseau installés, état systemd, exposition UFW |
| `ports.py` | Ports en écoute via `ss`, classification, déduplication |
| `logs.py` | Logs UFW — tentatives bloquées, bruteforce, top IPs/ports |
| `ddns.py` | Clients DDNS actifs, domaine configuré, ports ouverts croisés |
| `docker.py` | Contournement iptables, ports exposés par les containers |
| `virtualization.py` | Hyperviseurs actifs (libvirt/KVM, VirtualBox, VMware, LXD/LXC) et paquets Snap réseau |
| `firewall_stack.py` | Contournement iptables brut, règles nftables parallèles, détection ip_forward |
| `network_context.py` | Tableau d'interfaces réseau, connexions TCP établies, ports sensibles distants |
| `hardening.py` | Durcissement : mises à jour auto, AppArmor, rp_filter, redirections ICMP, log_martians, broadcast |
| `ipv6.py` | Cohérence ports IPv6 actifs / règles UFW v6 |
| `updates.py` | État des mises à jour système : paquets apt en attente (sécurité/réguliers), détection `unattended-upgrades` |
| `ssh.py` | Audit sécurité SSH : directives sshd_config, clés privées, authorized_keys, known_hosts |
| `file_perms.py` | Permissions fichiers sensibles : /etc/passwd, /etc/shadow, sudoers, clés hôte SSH |
| `user_accounts.py` | Audit comptes utilisateurs : UID 0 non-root, mots de passe vides, comptes expirés |
| `password_policy.py` | Politique mots de passe : module PAM qualité, minlen, PASS_MAX_DAYS |
| `kernel_modules.py` | Modules noyau risqués : cramfs, hfs, dccp, sctp, rds, tipc, usb_storage ; disponibilité mise à jour noyau apt (apt-cache policy / apt list --upgradable) |
| `cron_audit.py` | Sécurité cron : pipe-to-shell, scripts world-writable |
| `services_state.py` | État des services : services de sécurité activés au boot mais inactifs |
| `disk.py` | Santé disques : SMART (smartctl), attributs critiques, utilisation partitions ; support NVMe |
| `memory.py` | Mémoire & swap : détection usure SSD, swap injustifié, swappiness |
| `desktop_apps.py` | Détection applications de bureau : applis GUI connues en cours d'exécution (Steam, Discord, Zoom…) |
| `ntp.py` | Synchronisation NTP : systemd-timesyncd/chronyd/ntpd actif et synchronisé |
| `fail2ban.py` | Prévention intrusion Fail2ban : état service, jails actifs, détection jail SSH |
| `rootkit.py` | Scan rootkit & intégrité : installation rkhunter/chkrootkit, fraîcheur BDD, date dernier scan |
| `auditd.py` | Linux Audit Framework : installation, état service, règles chargées, surveillance fichiers sensibles |
| `secure_boot.py` | Secure Boot : état UEFI via mokutil/efivars/bootctl ; scoring adapté au profil |
| `file_integrity.py` | Intégrité des fichiers : installation AIDE/Tripwire, existence BDD, récence du dernier check |
| `ssl_certs.py` | Expiration certificats TLS/SSL : Let's Encrypt, `/etc/ssl/private` (snakeoil filtré), configs nginx/apache2/postfix |
| `systemd_timers.py` | Sécurité timers systemd : pipe-to-shell dans ExecStart, scripts world-writable, timers root utilisateur |
| `firmware.py` | Firmware & microcode : mises à jour fwupdmgr, paquet microcode CPU via dpkg |
| `iptables_nftables.py` | CHECK 46 : audit iptables/nftables quand UFW inactif — politique INPUT/FORWARD, conntrack, détection backend (iptables-legacy vs nftables) |
| `ipv6.py` | Cohérence ports IPv6 / règles UFW v6 ; champ `has_global_ipv6` ; link-local/ULA uniquement → INFO (pas WARN) |

---

## Structure du projet

```
bob/
├── __init__.py
├── __main__.py          # Orchestrateur (~400 lignes — coordination pure)
├── _paths.py            # Résolution des chemins de données
├── cli.py               # AuditConfig + parse_args()
├── config.py            # UserConfig, EmailStore
├── cron.py              # CronEntry, logique wizard planification, build_script_content()
├── cron_ui.py           # TUI curses pour --install-cron / --manage-cron
├── display.py           # Helpers affichage terminal (display_result, print_audit_summary…)
├── fixes.py             # Interface mode fix (interactif + auto-fix)
├── i18n.py              # t(key) avec notation pointée
├── manage_logs.py       # Interface --manage-logs, get_or_prompt_log_dir()
├── output.py            # Primitives terminal bas niveau
├── panorama.py          # build_panorama_rows()
├── registry.py          # ServiceRegistry.load()
├── report.py            # AuditReport + NullReport
├── report_markdown.py   # MarkdownReport, email HTML
├── scoring.py           # ScoreEngine, CheckResult, Finding, Deduction
├── sysinfo.py           # collect_system_info(), detect_network_context(), get_user_home()
├── checks/
│   ├── __init__.py
│   ├── _run.py          # Helper subprocess _run() partagé + env locale C
│   ├── firewall.py      # FirewallStatus + check_firewall() + check_rules()
│   ├── services.py      # ServiceSnapshot + check_services()
│   ├── ports.py         # PortsSnapshot + check_ports()
│   ├── logs.py          # LogsSnapshot + check_logs()
│   ├── ddns.py          # DdnsSnapshot + check_ddns()
│   ├── docker.py        # DockerSnapshot + check_docker()
│   ├── virtualization.py # VirtSnapshot + check_virtualization()
│   ├── firewall_stack.py # FirewallStackSnapshot + check_firewall_stack()
│   ├── network_context.py # NetworkContextSnapshot + check_network_context()
│   ├── hardening.py     # HardeningSnapshot + check_hardening()
│   ├── ipv6.py          # IPv6Snapshot + check_ipv6()
│   ├── updates.py       # UpdatesSnapshot + check_updates()
│   ├── ssh.py           # SshSnapshot + check_ssh()
│   ├── file_perms.py    # FilePermsSnapshot + check_file_perms()
│   ├── user_accounts.py # UserAccountsSnapshot + check_user_accounts()
│   ├── password_policy.py # PasswordPolicySnapshot + check_password_policy()
│   ├── kernel_modules.py # KernelModulesSnapshot + check_kernel_modules() — modules risqués + mise à jour noyau apt
│   ├── cron_audit.py    # CronAuditSnapshot + check_cron_audit()
│   ├── services_state.py # ServicesStateSnapshot + check_services_state()
│   ├── disk.py          # DiskSnapshot + check_disk() — SMART, partitions, NVMe
│   ├── memory.py        # MemorySnapshot + check_memory() — usure SSD, swappiness
│   ├── desktop_apps.py  # DesktopAppsSnapshot + check_desktop_apps() — détection applis GUI
│   ├── ntp.py           # NtpSnapshot + check_ntp() — état synchronisation NTP
│   ├── fail2ban.py      # Fail2banSnapshot + check_fail2ban() — service, jails, jail SSH
│   ├── rootkit.py       # RootkitSnapshot + check_rootkit() — rkhunter/chkrootkit
│   ├── ssl_certs.py     # SslCertsSnapshot + check_ssl_certs() — expiration certs (CHECK 43)
│   ├── systemd_timers.py # SystemdTimersSnapshot + check_systemd_timers() — sécurité timers (CHECK 44)
│   ├── firmware.py      # FirmwareSnapshot + check_firmware() — fwupd + microcode (CHECK 45)
│   └── iptables_nftables.py # IptablesNftablesSnapshot + check_iptables_nftables() — audit pare-feu brut (CHECK 46)
├── _tty.py              # read_line() — lecteur de ligne mode raw avec Esc-pour-annuler, repli input()
├── html_output.py       # build_html_output() — export HTML autonome (--html)
├── compare.py           # AuditBaseline (finding_keys) + AuditDelta (new/resolved keys) + rapport comparatif
├── correlation.py       # CorrelationRule + run_correlations() — 5 règles de risque composé
├── exposure.py          # Regroupement exposition ports — portée d'interface + niveau de risque
├── recurrence.py        # Suivi findings récurrents — compteurs consécutifs
├── plugin_checks.py     # PluginCheck + load_plugin_checks()
├── explain.py           # run_explain(), normalize_key(), EXPLAIN_KEYS — 112 clés dans 26 groupes
├── domain_scores.py     # compute_domain_scores(), render_domain_scores() — backup→disk
├── webhook.py           # build_generic_payload(), build_slack_payload(), send_webhook()
├── data/
│   ├── services.json            # Registre déclaratif des 32 services
│   ├── cis_refs.json            # Références CIS — 133 entrées {ref, code}
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
python3 --version   # 3.9+ requis
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
4200 passed in X.XXs
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
EN keys: 1527
FR keys: 1527
Missing in FR: none
```

---

## Ajouter une langue

### 1. Créer le fichier de locale

```bash
cp bob/locales/en.json bob/locales/de.json
```

### 2. Traduire toutes les valeurs

Le fichier contient ~1500 clés organisées en sections. Traduire toutes les valeurs en conservant les placeholders `{variable}` intacts.

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
  ├── ScoreEngine()
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
engine = ScoreEngine()
engine.apply(check_result)              # applique findings et déductions
engine.cap(maximum=3, key="firewall.inactive")  # plafonne si pare-feu inactif
engine.finalize()                       # applique le plafond, clamp à [0, 10]
apply_domain_score_override(engine)     # score global = moyenne des domaines actifs
                                        # DOIT être appelé après finalize()

score = engine.score         # int 0–10 — domain-averaged si override défini
level = engine.level         # RiskLevel.LOW / MEDIUM / HIGH / CRITICAL
raw   = engine._raw_score    # score brut pré-override (débogage uniquement)
```

**Contrat orchestrateur :** `apply_domain_score_override(engine)` depuis `bob.domain_scores` doit être appelé après `engine.finalize()`. Avant cet appel, `engine.score` retourne le score brut basé sur les déductions. Ne pas appeler `engine.set_global_score()` directement.

**Ensemble des domaines actifs :** seuls les domaines avec au moins un finding WARN ou ALERT comptent comme « actifs » pour la moyenne globale. Les domaines avec uniquement des findings INFO (service installé, rien d'actionnable) sont exclus. Note : une déduction avec une clé active toujours le domaine, quelle que soit le niveau du finding associé.

**Pondération égale des domaines :** tous les domaines actifs contribuent également à la moyenne globale — il n'y a pas de pondération par domaine. Une machine où seul SSH est dégradé et tous les autres domaines sont à 10/10 bénéficie de la dilution ; une machine avec les sept domaines actifs accorde le même poids au pare-feu qu'à la santé du disque. C'est la principale question architecturale pour la v0.3.0.

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

`$UFW_AUDIT_SHARE` peut pointer vers un répertoire de données partagé (ex. `/usr/local/share/bob/`). Elle prend la priorité sur le chemin embarqué dans le paquet si définie. Non utilisée avec pipx.

```python
# i18n.py
_share = os.environ.get("UFW_AUDIT_SHARE", "")
if _share:
    _LOCALES_DIR = Path(_share) / "locales"
else:
    _LOCALES_DIR = Path(__file__).parent / "locales"
```

---

## Variables d'environnement

| Variable | Effet |
|---|---|
| `UFW_AUDIT_SHARE` | Répertoire des données partagées (locales, services.json) — prioritaire sur le chemin embarqué si défini ; non utilisé avec pipx |
| `SUDO_USER` | Utilisateur réel sous sudo — utilisé pour le chemin de config et le rapport |
| `NO_COLOR` | Désactive les couleurs ANSI (standard) |

