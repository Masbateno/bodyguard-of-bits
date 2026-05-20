# BOB — Politique de sécurité

*[Read in English](SECURITY.md)*

## Versions supportées

Les correctifs de sécurité sont émis pour la dernière ligne de minor release uniquement. Les minor releases antérieures ne sont pas backportées.

| Version   | Supportée          |
|-----------|--------------------|
| 0.4.x     | ✅ courante         |
| 0.3.x     | ❌ fin de vie       |
| < 0.3.0   | ❌ fin de vie       |

Les correctifs sortent en `0.4.x+1`. Un breaking change bump le minor (`0.5.0`).

## Signaler une vulnérabilité

**N'ouvrez pas d'issue GitHub publique pour un signalement de sécurité.**

Signalez les problèmes de sécurité par email à :

```
cedricclauzel@mailo.com
```

avec le préfixe d'objet `[BOB security]`. Inclure :

  - Version BOB (`bob --version`)
  - Plateforme (distro + version, version du noyau)
  - Reproduction minimale (commandes, comportement attendu vs observé)
  - Évaluation d'impact telle que vous la voyez

Vous recevrez un acquittement sous **7 jours**. Un correctif ou plan de remédiation sera communiqué sous **30 jours** pour les problèmes haute sévérité (exécution de code arbitraire, escalade de privilèges, fuite de données sensibles). Les problèmes de moindre sévérité (déni de service contre l'audit lui-même, divulgation d'informations sur des valeurs sysctl publiques, etc.) sont traités au mieux sur le tracker d'issues publique une fois acquittés.

C'est un projet maintenu en solo. Merci d'être patient ; une assignation CVE n'est pas garantie pour chaque rapport.

## Modèle de menace

Cette section est la source faisant autorité pour « ce contre quoi BOB défend et ce contre quoi il ne défend pas ». À lire avant d'intégrer BOB à une pipeline de sécurité.

### Ce qu'est BOB

BOB est un outil **en lecture seule (audit-only)**. Il inspecte l'état du système Linux local et reporte les findings vers le terminal, un fichier de log, et optionnellement une sortie JSON ou un webhook sortant. Il est invoqué par un utilisateur privilégié (`sudo bob`) sur un système que l'utilisateur contrôle déjà.

BOB **n'est pas** :

  - un daemon qui écoute sur un port réseau (aucune surface d'attaque entrante) ;
  - un agent distant (aucune connexion command-and-control à distance) ;
  - un outil de défense active (BOB ne bloque pas de trafic, ne tue pas de processus, ne modifie pas de règles pare-feu de lui-même — le mode `--fix` demande confirmation à l'utilisateur pour chaque commande) ;
  - un outil de forensics (pas de chain-of-custody, pas de stockage de preuves immuable).

### Modèle d'adversaire

BOB pose trois hypothèses sur son environnement d'exécution :

  1. **L'utilisateur invocant est de confiance.** `sudo bob` tourne en tant que root par conception. Un utilisateur avec accès sudo a déjà le contrôle complet du système ; BOB n'est pas un pare-feu de privilèges contre lui.
  2. **La disposition du système de fichiers local est saine.** BOB lit `/etc/`, `/proc/`, `/var/log/`, `~/.ssh/`, etc. Si ces chemins ont été falsifiés par un attaquant qui a déjà root, les findings de BOB peuvent être trompeurs. BOB fait partie de la chaîne d'outils d'audit post-compromission, pas de détection pré-compromission.
  3. **Le gestionnaire de paquets de l'hôte est intact.** Les checks comme `apt-cache policy`, `fwupdmgr get-updates`, `systemctl is-active` reposent sur des binaires système légitimes. Un gestionnaire de paquets compromis qui ment trompera BOB.

### Frontières de confiance

BOB traverse trois frontières de confiance pendant une exécution :

| Frontière                       | Entrée vers BOB                                                                                            | Défense côté BOB                                                                                                                                                                                                                                                                |
|---------------------------------|------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Config user-contrôlée**       | `~/.config/bob/config.conf`, `services.d/*.json`, `checks.d/*.py`, `profiles/*.conf`                       | Validation JSON Schema stricte (`bob/data/schemas/`), sanitization ANSI (`bob.plugin_checks`), limites de taille de fichier, vérification d'identifiant Python sur `config_key`                                                                                                   |
| **Contenu de fichiers système** | `/etc/ssh/sshd_config`, `/var/log/auth.log`, fichiers cron, sudoers…                                       | Lectures bornées (`errors='replace'`, plafonds de taille, max lignes), les regex ne s'ancrent jamais sur du contenu user, `_C_LOCALE_ENV` pour subprocess afin d'éviter le parsing dépendant de la locale                                                                          |
| **Sortie de subprocess**        | `ufw status`, `ss -tulnp`, `iptables -L`, `journalctl`, `openssl x509` …                                   | Tous les appels subprocess ont `timeout=`, mode capture (pas de `shell=True` sauf dans `--fix` où les commandes sont explicitement approuvées par l'utilisateur), la sortie n'est jamais `eval`uée ni interpolée dans une autre commande                                            |

### Hors périmètre

  - **Compromission root préexistante.** BOB ne peut pas détecter un rootkit qui a remplacé les binaires sur lesquels il s'appuie (`ss`, `iptables`, …). Utilisez un scanner d'intégrité séparé (AIDE, Tripwire — BOB recommande d'installer ceux-ci).
  - **Attaques au niveau noyau.** BOB lit `/proc/sys` et lui fait confiance. Un module noyau malveillant peut mentir sur chaque valeur sysctl.
  - **Vulnérabilités au niveau applicatif.** BOB audite la surface de durcissement OS, pas la sécurité d'applications utilisateur arbitraires.

### Mode `--fix`

Le mode `--fix` affiche les commandes de remédiation et ne les exécute qu'après que l'utilisateur tape `y`. BOB **n'écrit jamais** vers des fichiers système en dehors de `~/.config/bob/` et du répertoire de log choisi par l'utilisateur sans confirmation explicite. Même en mode `--apply` (auto-fix), seules les commandes listées dans le texte de remédiation propre à BOB sont éligibles — il n'y a pas d'eval de messages de findings ni d'expansion shell de données dynamiques.

### Plugin checks (`~/.config/bob/checks.d/*.py`)

Les plugins Python custom sont chargés avec **limites de taille et sanitization ANSI** sur leur sortie, mais ils **NE SONT PAS sandboxés** : un plugin tourne avec les mêmes privilèges que BOB lui-même (typiquement root). Faites confiance à vos sources de plugins comme à tout autre code que vous exécuteriez sous `sudo`.

Une future version majeure pourra introduire un runner de plugins en mode restreint (pas d'écriture filesystem, pas de subprocess), mais c'est hors périmètre pour la ligne 0.4.x.

## Surface réseau

Par défaut, BOB effectue **deux** appels HTTPS sortants :

  1. **Lookup d'IP publique** au démarrage de l'audit (providers par défaut : `api.ipify.org`, `icanhazip.com`, `ifconfig.me`). Utilisé pour classifier le contexte réseau (local vs public). Chaque provider a un timeout de 3 secondes.
  2. **Webhook POST** si `--webhook=URL` est donné. POST de payload `application/json` vers l'URL fournie par l'utilisateur.

Les deux peuvent être désactivés avec `--offline` (ou `-o`). En mode `--offline`, BOB effectue **zéro** connexion réseau sortante. C'est le réglage recommandé pour les sandboxes CI / build de distro / environnements air-gapped.

Pas de télémétrie, pas d'analytics, pas de vérification de mise à jour automatique, pas de logging distant : BOB ne phone jamais home.

## Manipulation des données

  - **Rapports** : Les rapports détaillés `-d` sont écrits vers le répertoire de log configuré par l'utilisateur (par défaut : `~/.local/share/bob/logs/`). Les permissions de fichier sont `0644` (lisible par l'utilisateur propriétaire ; root si invoqué sous sudo et aucun log dir n'est surchargé).
  - **Config** : `~/.config/bob/config.conf` est `0600` (propriétaire uniquement).
  - **Baseline** : `~/.config/bob/last_baseline.json` est `0600`. Contient uniquement des clés de findings, scores, et listes de ports — pas de secrets, pas de contenus de fichiers, pas de PII autre que le nom d'hôte.
  - **Historique** : `~/.config/bob/history.jsonl` est `0600`. Une ligne par audit : timestamp + score + niveau. Rotation à 1000 entrées.

Quand BOB est invoqué via `sudo`, les fichiers dans `~/.config/bob/` sont automatiquement chownés de retour vers `$SUDO_USER` (depuis v0.3.6) afin qu'ils restent lisibles/éditables sans sudo par la suite.

## Recommandations de défense en profondeur (pour les packageurs)

Si BOB est packagé pour une distro qui supporte le MAC (AppArmor sur Ubuntu/Debian, SELinux sur RHEL/Fedora) :

  - Livrer le profil AppArmor optionnel (`debian/apparmor.d/bob` une fois packagé) en mode `complain` par défaut ; offrir `enforce` en opt-in afin que les utilisateurs aventureux aident à débusquer les faux positifs.
  - Le profil DOIT autoriser la lecture sur `/etc/`, `/proc/`, `/sys/`, `/var/log/`, `~/.config/bob/`, `~/.ssh/`, et l'exécution sur les outils système que BOB invoque (~58 binaires couvrant pare-feu, systemd/journal, framework audit, politique MAC, durcissement noyau, antivirus, scan rootkit, NTP, Secure Boot, gestionnaire de paquets). La **liste canonique et exhaustive** est le profil `debian/apparmor.d/bob` packagé — adapter les chemins selon le layout de la distro. Un échantillon représentatif : `ufw`, `ss`, `iptables`, `ip6tables`, `nft`, `systemctl`, `journalctl`, `openssl`, `smartctl`, `fwupdmgr`, `aa-status`, `sestatus`, `mokutil`, `bootctl`, `sysctl`, `ip`, `swapon`, `timedatectl`, `chronyc`, `rkhunter`, `chkrootkit`, `clamscan`, `freshclam`, `aide`, `auditctl`, `fail2ban-client`, `postconf`, `snap`, `dpkg`, `apt-cache`.
  - Le trafic réseau sortant (HTTPS) doit être autorisé pour le lookup d'IP publique et la livraison webhook, sauf si les déploiements reposent exclusivement sur le mode `--offline`.
  - Recommander l'installation de BOB avec `pipx` (chemin d'installation upstream par défaut) afin qu'il vive dans `~/.local/pipx/venvs/bodyguard-of-bits/` plutôt que dans un environnement Python système partagé.

## Politique de divulgation

  - Divulgation coordonnée préférée.
  - Durée d'embargo : 30 jours de l'acquittement au correctif public, extensible par accord mutuel.
  - Crédit : les rapporteurs sont crédités dans le changelog sauf s'ils demandent l'anonymat.

## Remerciements

Les chercheurs en cryptographie ou sécurité qui ont signalé des vulnérabilités à BOB seront listés ici.

*(aucun pour l'instant — soyez le premier)*

---

© 2026 Cédric Clauzel
