*[Read in English](README_TECH.md)* · *[Vue d'ensemble](../README_FR.md)*

# BOB — Bodyguard Of Bits

![License](https://img.shields.io/badge/license-MIT-green)
![Release](https://img.shields.io/badge/version-v0.5.5-brightgreen)
![CI](https://github.com/Masbateno/bodyguard-of-bits/actions/workflows/tests.yml/badge.svg)
![Integration](https://github.com/Masbateno/bodyguard-of-bits/actions/workflows/integration.yml/badge.svg)
![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu%20%7C%20Mint%20%7C%20Kali%20%7C%20Fedora-informational)
![Language](https://img.shields.io/badge/language-Python%203.10%2B-yellow)

BOB est un auditeur de durcissement Linux pour les admins système et power users. Il exécute 43 vérifications sur 7 domaines de score, mappe les résultats aux benchmarks CIS quand applicable, et fournit des explications claires avec des commandes de correction prêtes à l'emploi.

---

## Fonctionnalités

### Audit principal

- **Bannière ASCII** avec informations système — distro, hôte, version UFW, utilisateur, date
- **Vérification du statut UFW** — actif/inactif, politique par défaut entrante
- **Analyse des règles UFW** — règles en doublon, `allow from any` sans restriction de port, cohérence IPv6
- **Score contextuel** — détection du contexte réseau (IP publique directe vs NAT) ; pénalités doublées sur les machines exposées sur internet ; pare-feu inactif plafonne le score à 3/10
- **Score de sécurité** 0–10 avec niveau de risque : FAIBLE / MOYEN / ÉLEVÉ / CRITIQUE ; findings répartis en *Action requise* / *Améliorations possibles* / *Configuration normale*
- **Profils d'audit** — `server` (défaut), `desktop`, `container` ; alias `workstation` conservé ; profil actif affiché dans la boîte de synthèse
- **Cartographie CIS inline** — chaque finding affiche son code CIS `[CIS:X.Y.Z]` dans la boîte de synthèse ; référence complète en mode `--verbose` ; 137 entrées (99 CIS formels, 34 best-practice, 4 Docker)
- **5 en-têtes de groupes thématiques** — sortie organisée en : FIREWALL & RÉSEAU / EXPOSITION & SERVICES / CONTRÔLE D'ACCÈS / DURCISSEMENT SYSTÈME / DÉTECTION & SANTÉ
- **`--target N`** — objectif de score (1–10) ; affiché dans la boîte de synthèse ; retourne le code de sortie 4 si score < cible (intégration CI)

### Réseau & pare-feu

- **32 services réseau connus** détectés avec analyse d'exposition UFW et contexte de risque à deux axes (exposition + menace) pour les services critiques et élevés ; services CRITICAL/HIGH installés mais inactifs émettent ⚠ + bloc de contexte de risque
- **Panorama des services** — tableau compact des 32 services après l'audit : SERVICE / STATUT / PORT(S) / UFW ; services non installés affichés en grisé
- **Audit iptables/nftables** — quand UFW est inactif : détecte le backend actif (iptables vs nftables) ; vérifie les politiques par défaut INPUT et FORWARD ; contrôle la présence du conntrack stateful ; WARN −1 pt par politique permissive
- **Docker** — détection du contournement iptables et liste des ports exposés par les containers en cours d'exécution
- **Virtualisation** — détecte les hyperviseurs actifs (libvirt/KVM, VirtualBox, VMware, LXD/LXC) et les paquets Snap réseau susceptibles de créer des interfaces bridge et de contourner UFW
- **Ports en écoute** — passe unique unifiée ; ports éphémères et système ignorés proprement ; NetBIOS géré avec avertissement contextuel
- **Détection DDNS / exposition externe** — détecte les clients DDNS actifs (ddclient, inadyn, No-IP, DuckDNS) ; extrait le domaine configuré ; croise avec les règles UFW ALLOW sans restriction pour identifier les ports exposés sur internet
- **Classification d'exposition** par service : `ouvert sur internet` / `réseau local uniquement` / `bloqué par UFW` / `pas de règle`
- **Cohérence IPv6** — détecte les ports IPv6 actifs sans règle UFW v6 correspondante ; IPv6 désactivé globalement mais ports en écoute présents ; adresses link-local/ULA uniquement → INFO
- **Contrôle niveau de journalisation UFW** — `off` → ALERT −2 pts (aucune visibilité sur le trafic bloqué) ; `low`/`medium` → OK ; `high`/`full` → INFO
- **Regroupement exposition des ports** — regroupe les services en écoute exposés par portée d'interface et niveau de risque ; démons OS connus sur ports système classifiés séparément des apps utilisateur

### Durcissement système

- **Vérification durcissement** — unattended-upgrades, mode AppArmor, rp_filter, redirections ICMP, log_martians, broadcast ICMP ; déductions scorées pour les paramètres les plus impactants
- **Audit de sécurité SSH** — analyse complète de `sshd_config` (15 directives + Ciphers/MACs/KEX faibles) ; audit des clés privées (type, taille, passphrase) ; inspection `authorized_keys` ; vérification côté client `~/.ssh/config` ; comptage `known_hosts` ; suggestions d'installation adaptées à la distro
- **Fichiers sensibles & sudoers** — audit des permissions de `/etc/passwd`, `/etc/shadow`, `/etc/gshadow`, `/etc/group`, `/etc/sudoers` ; permissions des clés hôtes SSH ; détection de `NOPASSWD:ALL` dans sudoers et sudoers.d
- **Audit des mises à jour système** — paquets de sécurité en attente via `apt-get -s upgrade` (−2 pts fixe) ; absence de `unattended-upgrades` combinée à des mises à jour de sécurité en attente (−1 pt composé) ; mises à jour régulières → INFO uniquement
- **Audit umask système** — lit le umask depuis `/etc/login.defs`, PAM, `/etc/profile`, RC shells et processus courant ; umask permissif (0002/0000) → WARN −1 pt ; sources conflictuelles → WARN −1 pt
- **Secure Boot** — état UEFI via `mokutil --sb-state` / `efivars` / `bootctl` ; WARN −1 pt si désactivé sur desktop ; INFO sur server/VM ou BIOS/inconnu
- **Audit firmware & microcode** — `fwupdmgr` firmware device en attente ; paquet microcode CPU (Intel/AMD) ; WARN −1 pt si absent ou obsolète
- **Expiration certificats TLS/SSL** — analyse Let's Encrypt, `/etc/ssl/private`, directives nginx/apache2/postfix ; expiré → ALERT −2 pts ; <7 j → ALERT −2 pts ; <30 j → WARN −1 pt ; total plafonné à −4 pts ; liens symboliques cassés gérés
- **Sécurité timers systemd** — curl/wget pipé vers un shell dans ExecStart → WARN −2 pts ; scripts world-writable dans ExecStart → WARN −1 pt ; timers root créés par l'utilisateur sans `User=` → INFO

### Détection & surveillance

- **Logs UFW** — parse `/var/log/ufw.log` sur une période configurable (`--log-days=N`, défaut 7 jours) ; total des tentatives bloquées, top IPs sources avec géolocalisation, top ports ciblés, détection bruteforce (>10 tentatives/60 s), tentatives sur ports de services installés
- **Analyse auth.log SSH** — parse `/var/log/auth.log` ; détection brute-force (>10 tentatives échouées depuis la même IP en 60 s → ALERT −2 pts) ; dernières connexions réussies ; top sources d'échec
- **Géolocalisation IP** — IPs sources enrichies avec pays et opérateur via GeoIP2 (optionnel, `python3-geoip2` + base GeoLite2) ; plages privées identifiées comme réseau local ; résultats mis en cache par session
- **Dominance source locale IoT** — détecte quand une seule IP privée représente ≥ 70 % du trafic UFW bloqué sur ≥ 50 entrées de log (WARN, −1 pt) ; typique des appareils IoT qui scannent le LAN
- **Synchronisation NTP** — systemd-timesyncd, chronyd ou ntpd ; WARN −1 pt si désactivé ou non synchronisé
- **Prévention d'intrusion Fail2ban** — installation, état du service, jails actifs, présence d'un jail SSH ; WARN −1 pt si inactif ou aucun jail
- **Scan rootkit & intégrité** — détection rkhunter/chkrootkit ; WARN −1 pt pour base obsolète (≥7 jours), scan absent ou trop ancien (>30 jours)
- **Linux Audit Framework (auditd)** — installation, état du service, règles chargées, couverture de `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` ; WARN −1 pt chacun pour service inactif, aucune règle, fichiers non couverts (profil server uniquement)
- **Intégrité des fichiers (AIDE/Tripwire)** — installation, existence de la base, récence du dernier check ; WARN −1 pt si base absente ou check absent/trop ancien (>30 jours)
- **Audit sécurité Samba** — SMB1 (ALERT −2 pts) ; mots de passe nuls (ALERT −3 pts) ; signature serveur désactivée (WARN −1 pt) ; partages accessibles en écriture/lecture par l'invité ; domaine `samba` dédié
- **Audit antivirus ClamAV** — installation, fraîcheur de la base virus via mtime (WARN/ALERT selon ancienneté), statut démon, date du dernier scan
- **Exposition SMTP locale** — détecte les MTA (Postfix, Exim, Sendmail) en écoute sur toutes les interfaces vs localhost uniquement ; WARN −1 pt si exposition publique
- **Moteur de corrélation de signaux** — 5 règles de risque composé (root+sans-fail2ban, auth-password+brute-force, root+password, NOPASSWD+SUID, logging-off+sans-fail2ban+sans-auditd) ; évalué post-audit sur les findings ALERT+WARN actifs
- **Suivi des findings récurrents** — compteur d'apparitions consécutives par clé ALERT/WARN ; stocké dans `~/.config/bob/recurrence.json`
- **Détection d'applications de bureau** — applis GUI connues (Steam, Discord, Zoom, Signal, VLC, Spotify, Slack, Telegram, Chrome, Firefox…) en cours d'exécution ; findings INFO, sans déduction

### Sortie & UX

- **Interface bilingue** — détection automatique depuis `$LC_ALL`/`$LC_MESSAGES`/`$LANG` (POSIX) ; retombe sur l'anglais quand la locale est `C`/`POSIX` ou non supportée. Forcer avec `--french` ou `--lang=en`
- **Mode sans couleur** — `--no-color` pour une sortie propre dans les pipes et fichiers log
- **Mode fix** — section interactive après le résumé ; chaque correction automatisable demande une confirmation `[y/N]` ; `--fix` seul affiche un aperçu sans exécuter ; `--fix --apply --yes` confirme tout avec journal d'audit
- **`--explain KEY`** — explication structurée par constat (POURQUOI / COMMENT CORRIGER / référence CIS) ; 116 clés dans 29 groupes ; 19 clés avec sections par profil ; TUI interactif ; sans droit root ; `--explain list` liste toutes les clés
- **Scores par domaine** — sous-scores 0–10 (SSH / Samba / Fichiers & Accès / Mises à jour / Durcissement / Santé Disque / Pare-feu & Services) ; score global = moyenne des scores de domaine actifs (un domaine devient actif dès qu'un check émet `OK`, `WARN` ou `ALERT` — les domaines `INFO`-only restent cachés ; `OK` a été ajouté au set actif en v0.4.6 pour corriger une inversion de score après remédiation) ; plafonds par outil pour éviter la double pénalité (rootkit, ClamAV, intégrité fichiers plafonnés à 1 pt de déduction chacun) ; barre █/░ après l'audit ; inclus dans JSON et webhook
- **Webhooks** — `--webhook URL` envoie le résultat en JSON ; formats générique et Slack (auto-détecté) ; `--webhook-format=auto|generic|slack`
- **Export HTML `--html`** — fichier HTML autosuffisant (sans JS, sans ressources externes) ; cercle de score coloré ; badges ALERT/WARN/INFO/OK ; tableau déductions ; protection XSS
- **`--format=FORMAT`** — flag unifié : `json | json-full | csv | markdown | html` ; anciens flags conservés comme aliases
- **`--check LIST` / `--skip LIST`** — n'exécuter que les checks nommés ou les exclure ; mutuellement exclusifs ; `--check=list` affiche les 34 noms de sections
- **`--output-dir PATH`** — surcharger le répertoire de sauvegarde pour l'exécution courante ; sans persistance
- **Rapport comparatif** — baseline enregistrée après chaque audit ; au prochain lancement : delta de score, variations alertes/avertissements, ports apparus/fermés, services démarrés/arrêtés ; clés ALERT+WARN nouvelles et résolues suivies séparément
- **Historique des scores** — `--history` affiche les N derniers scores en sparkline (▁▂▃▄▅▆▇█) avec dates ; rotation automatique à 1000 entrées
- **Liste d'exceptions** — `--ignore KEY` ajoute une clé dans `ignore.yml` ; `--show-ignored` liste les exceptions actives ; les findings correspondants sont masqués sans être scorés
- **Mode `--diff`** — lance l'audit silencieusement et affiche uniquement le delta (score, alertes, avertissements, INFO)
- **`--breakdown` / `-B`** — lance l'audit silencieusement et affiche le chemin complet de calcul du score : toutes les déductions (clé · domaine · points · contexte), plafonds par outil, plafond moteur, score brut, scores par domaine avec barres de progression, surcharge de moyenne, score final coloré
- **API Plugin** — déposer un fichier Python dans `~/.config/bob/checks.d/` pour ajouter une vérification personnalisée ; fail-safe (les exceptions n'interrompent jamais l'audit) ; séquences ANSI nettoyées

### Automatisation

- **Rapport détaillé** — fichier log horodaté avec en-tête ASCII art, informations système, findings et recommandations ; créé avec `-d` ; nom : `bob_YYYYMMDD_HHMMSS.log`
- **`--manage-logs`** — interface interactive pour lister, prévisualiser et supprimer les rapports ; prévisualisation scrollable avec bascule résumé/complet
- **`--install-cron`** — wizard de planification : nom du cron, type de planning (quotidien / jours spécifiques / expression cron personnalisée), heure et email optionnel ; détection automatique du MTA (Postfix, Exim, msmtp, ssmtp) — avertit si aucun `sendmail` trouvé ; aperçu en langage naturel ; TUI curses avec repli texte ; crons nommés dans `/etc/cron.d/bob-{nom}`
- **`--manage-cron`** — TUI en boucle : lister, modifier planning/email, supprimer des crons ; carnet d'adresses email accessible depuis le menu, même sans cron installé

---

## Services détectés

| Service                          | Port par défaut      | Risque   | Contexte                                                                           |
|----------------------------------|----------------------|----------|------------------------------------------------------------------------------------|
| SSH Server                       | 22/tcp               | Critique | Très ciblé par les scans automatisés ; accès shell complet si compromis            |
| VNC Server                       | 5900/tcp             | Critique | Souvent sans chiffrement, auth faible ; équivalent à un accès physique             |
| Samba (partage fichiers Windows) | 445/tcp, 139/tcp     | Critique | Conçu pour LAN uniquement ; vecteur ransomware (EternalBlue/WannaCry) si exposé    |
| FTP Server                       | 21/tcp               | Critique | Protocole non chiffré ; credentials et fichiers transmis en clair                  |
| MySQL / MariaDB                  | 3306/tcp             | Critique | Auth par mot de passe, historique CVE ; exfiltration complète si exposé            |
| PostgreSQL                       | 5432/tcp             | Critique | Auth configurable ; RCE possible via pg_execute_server_program                     |
| Redis                            | 6379/tcp             | Critique | Pas d'auth par défaut historiquement ; RCE documenté et exploité activement        |
| Cockpit (admin web)              | 9090/tcp             | Élevé    | Interface d'admin système ; contrôle complet si compromis                          |
| WireGuard VPN                    | 51820/udp            | Élevé    | Exposition internet intentionnelle ; accès réseau interne complet si clés volées   |
| Home Assistant                   | 8123/tcp             | Élevé    | Contrôle équipements physiques (serrures, alarmes) ; accès réseau local            |
| Nextcloud                        | 80/tcp, 443/tcp      | Élevé    | Serveur de fichiers personnel ; accès fichiers/contacts/calendriers si compromis   |
| Mosquitto (MQTT)                 | 1883/tcp, 8883/tcp   | Élevé    | Pas d'auth par défaut ; contrôle équipements IoT si exposé                         |
| Apache Web Server                | 80/tcp, 443/tcp      | Moyen    | Exposition web standard ; risque selon le contenu hébergé                          |
| Nginx Web Server                 | 80/tcp, 443/tcp      | Moyen    | Exposition web standard ; risque selon le contenu hébergé                          |
| Jellyfin                         | 8096/tcp             | Moyen    | Accès bibliothèque média ; pas de données système critiques                        |
| Plex Media Server                | 32400/tcp            | Moyen    | Accès bibliothèque média ; pas de données système critiques                        |
| Transmission (UI web)            | 9091/tcp             | Moyen    | Contrôle téléchargements ; accès fichiers limité au répertoire torrent             |
| qBittorrent (UI web)             | 8080/tcp             | Moyen    | Contrôle téléchargements ; accès fichiers limité au répertoire torrent             |
| Gitea                            | 3000/tcp             | Moyen    | Forge Git ; désactiver l'inscription publique si non nécessaire                    |
| Avahi (découverte réseau local)  | 5353/udp             | Faible   | mDNS LAN uniquement ; pas d'accès aux données, découverte seulement                |
| CUPS (impression réseau)         | 631/tcp              | Faible   | Écoute sur localhost par défaut ; risque négligeable si non exposé                 |
| Syncthing                        | 8384/tcp, 22000/tcp  | Faible   | UI web sur localhost par défaut ; port de sync potentiellement exposé              |
| Telnet Server                    | 23/tcp               | Critique | Protocole en clair ; credentials et trafic visibles sur le réseau                  |
| RDP / xRDP                       | 3389/tcp             | Critique | Bureau à distance ; ciblé par brute-force et exploits de type BlueKeep             |
| MongoDB                          | 27017/tcp            | Critique | Pas d'auth par défaut (versions anciennes) ; accès DB complet si exposé            |
| Elasticsearch                    | 9200/tcp             | Critique | Pas d'auth par défaut ; API REST expose l'intégralité des index                    |
| Memcached                        | 11211/tcp+udp        | Critique | Pas d'auth ; utilisé dans les attaques d'amplification DDoS si exposé              |
| SMTP / Postfix                   | 25/tcp               | Élevé    | Risque open relay ; source de spam ou pivot si mal configuré                       |
| NFS Server                       | 2049/tcp+udp         | Élevé    | Conçu pour LAN ; accès filesystem complet si exposé sans auth                      |
| Jenkins                          | 8080/tcp             | Élevé    | Console CI/CD ; risque RCE via script console ; admin souvent sans auth            |
| OpenVPN                          | 1194/udp             | Moyen    | Exposition internet intentionnelle ; accès réseau interne complet si clés volées   |
| Squid Proxy                      | 3128/tcp             | Moyen    | Risque open proxy si non restreint ; peut exposer des services internes            |

> **ℹ Note sur la couverture des services :** La détection et la classification des services suivants ont été validées par des tests réels : SSH, Samba, Avahi, CUPS, Redis, WireGuard, Docker, Mosquitto, Syncthing, Nginx. Les autres services sont implémentés mais pas encore validés par un protocole de test formel. Si vous utilisez l'un de ces services et observez un comportement incorrect, merci d'ouvrir une issue sur GitHub.

---

## Prérequis

- Linux — utilisé au quotidien sur Linux Mint 22.3 + Debian 13.4.0 ; validé en CI sur Debian 12/13, Ubuntu 22.04/24.04/25.04, Kali Rolling, Fedora 41
- Python 3.10+
- `ss` recommandé (paquet `iproute2`) — disponible par défaut sur les systèmes modernes
- `python3-geoip2` + base GeoLite2 recommandés pour la géolocalisation IP (optionnel) : `sudo apt install python3-geoip2 geoip-database`
- `docker` CLI pour l'analyse Docker (optionnel)

---

## Installation

### Prérequis

- Linux — utilisé au quotidien sur Linux Mint 22.3 + Debian 13.4.0 ; validé en CI sur Debian 12/13, Ubuntu 22.04/24.04/25.04, Kali Rolling, Fedora 41
- pipx *(installateur d'applications Python isolées)* :

```bash
sudo apt install pipx && pipx ensurepath
```

> Ouvrir un nouveau terminal après `pipx ensurepath` pour activer le PATH.

### Installer

```bash
pipx install bodyguard-of-bits
```

### Activer sudo + autocomplétion bash

pipx installe le binaire dans `~/.local/bin/`, absent du PATH restreint de sudo.
`--install-completion` crée le lien symbolique `/usr/local/bin/bob` et installe le script d'autocomplétion bash :

```bash
sudo ~/.local/bin/bob --install-completion
source /etc/bash_completion.d/bob
```

Après cette étape, `sudo bob` fonctionne normalement et `bob --<TAB>` complète les options.

---

## Désinstallation

```bash
pipx uninstall bodyguard-of-bits
```

---

## Utilisation

```bash
# Audit standard
sudo bob

# Audit en français
sudo bob --french

# Mode verbeux — détails techniques et tableau des ports
sudo bob -v

# Mode détaillé — génère un fichier rapport complet
sudo bob -d

# Mode fix — propose et applique les corrections interactivement
sudo bob -f

# Mode fix — applique toutes les corrections sans confirmation
sudo bob -f -y

# Sortie sans couleur (utile pour les pipes et la redirection)
sudo bob -n > audit.txt

# Analyser les logs sur 14 jours au lieu de 7
sudo bob --log-days=14

# Reconfigurer les ports personnalisés
sudo bob -r

# Mode silencieux — aucune sortie, utilisez le code de retour
sudo bob -q; echo $?   # 0=propre, 1=avertissements, 2=alertes, 3=erreur

# Désactiver la résolution d'IP publique (machine isolée ou sans accès HTTP sortant)
sudo bob --offline
sudo bob -o

# Afficher la version (sans sudo)
bob -V

# Afficher l'aide (sans sudo)
bob -h

# Gérer les rapports sauvegardés interactivement
sudo bob --manage-logs

# Configurer un audit automatique (wizard de planification)
sudo bob --install-cron

# Lister, modifier ou supprimer les crons installés
sudo bob --manage-cron

# Installer l'autocomplétion bash et créer le lien symbolique sudo PATH (une seule fois après pipx install)
sudo bob --install-completion
```

> Les notifications email nécessitent une configuration Postfix fonctionnelle. Voir [AUTOMATION_FR.md](AUTOMATION_FR.md) pour les instructions pas à pas (installation, relais SMTP, réécriture expéditeur, test).

Les options se combinent :

```bash
sudo bob --french -v -d -f
```

---

## Configuration des ports personnalisés

Quand un service est détecté sur un port non standard (ex. SSH sur 2222), le script propose de sauvegarder le port. La réponse est sauvegardée dans `~/.config/bob/config.conf` et réutilisée lors des audits suivants. Pour reconfigurer :

```bash
sudo bob -r
```

---

## Exemple de sortie

Exemple (tronqué pour la lisibilité) :

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                         ██████╗   ██████╗  ██████╗                          ║
║                         ██╔══██╗ ██╔═══██╗ ██╔══██╗                         ║
║                         ██████╔╝ ██║   ██║ ██████╔╝                         ║
║                         ██╔══██╗ ██║   ██║ ██╔══██╗                         ║
║                         ██████╔╝ ╚██████╔╝ ██████╔╝                         ║
║                         ╚═════╝   ╚═════╝  ╚═════╝                          ║
║                                                                              ║
║                           — Bodyguard Of Bits —                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  BOB v0.5.5  │  Auditeur de durcissement Linux                               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  System        : Ubuntu 24.04 LTS                                            ║
║  Host          : my-machine                                                  ║
║  UFW           : v0.36.2                                                     ║
║  User          : alice                                                       ║
║  Date          : 17/05/2026 10:00                                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

┌──────────────────────────────────────────────────────────────────────────────┐
│  STATUT DU PARE-FEU                                                          │
└──────────────────────────────────────────────────────────────────────────────┘

✔ [OK] UFW est installé
✔ [OK] Pare-feu UFW actif
✔ [OK] Politique par défaut : connexions entrantes bloquées (recommandé)

┌──────────────────────────────────────────────────────────────────────────────┐
│  ANALYSE DES RÈGLES UFW                                                      │
└──────────────────────────────────────────────────────────────────────────────┘

✔ [OK] Aucune règle UFW en doublon détectée
✔ [OK] Aucune règle 'allow from any' sans restriction de port détectée
✔ [OK] Configuration IPv6 cohérente avec les règles UFW

┌──────────────────────────────────────────────────────────────────────────────┐
│  ANALYSE DES SERVICES RÉSEAU                                                 │
└──────────────────────────────────────────────────────────────────────────────┘

  ▶ SSH Server
    ┄ Contexte de risque — CRITIQUE
    Exposition        : Très ciblé par les scans automatisés et les attaques brute-force
    Menace potentielle : Accès shell complet à la machine, élévation de privilèges

✖ [ALERTE] Port 22/tcp — ouvert sur internet — aucune restriction source dans UFW

  ▶ Nginx Web Server
✔ [OK] Service actif et configuré pour démarrer automatiquement au boot
⚠ [ATTENTION] Port 80/tcp — ouvert sur internet — aucune restriction source dans UFW

  ▶ Redis
    ┄ Contexte de risque — CRITIQUE
    Exposition        : Sans authentification par défaut historiquement, très souvent mal configuré
    Menace potentielle : Accès en lecture/écriture à toutes les données, exécution de code à distance (RCE)

✔ [OK] Service actif et configuré pour démarrer automatiquement au boot
ℹ [INFO] Port 6379/tcp — couvert par la politique de refus par défaut (pas de règle UFW explicite nécessaire)

┌──────────────────────────────────────────────────────────────────────────────┐
│  PANORAMA DES SERVICES                                                       │
└──────────────────────────────────────────────────────────────────────────────┘

  SERVICE                           STATUT         PORT(S)               UFW
  ────────────────────────────────  ─────────────  ────────────────────  ───
  SSH Server                        ACTIF          22/tcp                ✖
  Nginx Web Server                  ACTIF          80/tcp, 443/tcp       ⚠
  Redis                             ACTIF          6379/tcp              ✖
  ...

┌──────────────────────────────────────────────────────────────────────────────┐
│  ANALYSE DES PORTS EN ÉCOUTE                                                 │
└──────────────────────────────────────────────────────────────────────────────┘

ℹ [INFO] Port système interne — aucun risque : 53/udp (DNS)
ℹ [INFO] Port 25/tcp — lié uniquement à localhost — pas d'exposition externe
✔ [OK] Tous les ports en écoute sur 0.0.0.0 sont couverts par une règle UFW

┌──────────────────────────────────────────────────────────────────────────────┐
│  ANALYSE DES LOGS UFW                                                        │
└──────────────────────────────────────────────────────────────────────────────┘

  Période analysée : 7 jour(s) — 7 jour(s) de logs disponibles

✔ [OK] Activité normale — 47 tentative(s) bloquée(s) sur 7 jour(s), aucune menace détectée
ℹ [INFO] Top IPs sources : 203.0.113.42 (US, Virginia) — 18 tentative(s)
ℹ [INFO] Top ports ciblés : 22/tcp — 31 tentative(s)

╔══════════════════════════════════════════════════════════════════════════════╗
║  Score de sécurité : 6/10                                                    ║
║  Niveau de risque : ✖ MOYEN                                                  ║
║  Contexte réseau : 🌐 Exposé sur internet                                    ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  ✖ Action requise                                                            ║
║    ✖  Port 22/tcp — ouvert sur internet — aucune restriction…                ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  ⚠ Améliorations possibles                                                   ║
║    ⚠  Port 80/tcp — ouvert sur internet — aucune restriction…                ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Décomposition du score                                                      ║
║    -2  SSH Server 22/tcp exposé sur internet                                 ║
║    -1  Nginx Web Server 80/tcp exposé sur internet                           ║
║    -1  SSH Server 22/tcp exposé sur internet                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

  Corrections nécessaires. Traitez en priorité les éléments marqués "Action requise".
```

---

## Fichiers de rapport

Avec `-d`, un rapport horodaté est créé dans un répertoire configurable (demandé au premier lancement, sauvegardé dans `config.conf`) :

```
bob_20260517_100000.log
```

Le rapport s'ouvre avec un en-tête ASCII art sur 62 caractères et contient : informations système, tous les findings horodatés, liste complète des ports en écoute, analyse détaillée des logs (top IPs avec géolocalisation, top ports, bruteforce, tentatives sur les ports de services installés), contexte de risque pour les services critiques et élevés, résumé du score.

---

## Référence des options

| Option                  | Description                                                        |
|-------------------------|--------------------------------------------------------------------|
| *(sans option)*         | Audit standard                                                     |
| `-v`, `--verbose`       | Afficher les détails techniques (tableau des ports, exposition)    |
| `-d`, `--detailed`      | Générer un fichier rapport complet                                 |
| `-q`, `--quiet`         | Supprimer toute sortie — utiliser le code de retour                |
| `-f`, `--fix`           | Proposer et appliquer les corrections interactivement              |
| `-y`, `--yes`           | Appliquer toutes les corrections sans confirmation (avec `-f`)     |
| `-r`, `--reconfigure`   | Reconfigurer tous les ports personnalisés                          |
| `-n`, `--no-color`      | Désactiver la sortie ANSI couleur                                  |
| `--format=FORMAT`       | Flag unifié : `json \| json-full \| csv \| markdown \| html`      |
| `--json`                | Exporter le résumé en JSON (alias `--format=json`)                 |
| `--json-full`           | Exporter l'audit complet en JSON (alias `--format=json-full`)      |
| `--explain=KEY`         | Afficher l'explication d'une clé de constat (`--explain list` liste tout) |
| `-B`, `--breakdown`     | Audit silencieux — afficher le chemin complet de calcul du score (déductions, plafonds, domaines, score final) |
| `--diff`                | Audit silencieux — afficher uniquement le delta de la baseline      |
| `--webhook=URL`         | Envoyer le résultat d'audit en JSON à l'URL après chaque audit     |
| `--webhook-format=FMT`  | Format webhook : `auto` (défaut), `generic` ou `slack`            |
| `--log-days=N`          | Analyser les logs sur N jours (défaut : 7)                         |
| `-o`, `--offline`       | Désactiver la résolution d'IP publique et l'appel webhook (aucun appel HTTP) |
| `--manage-logs`         | Interface interactive pour lister, prévisualiser et supprimer les rapports |
| `--install-cron`        | Configurer un audit nocturne automatique (cron)                    |
| `--install-completion`  | Installer l'autocomplétion bash et créer le lien symbolique sudo PATH |
| `--french`              | Passer l'interface en français                                     |
| `-V`, `--version`       | Afficher la version et quitter (sans sudo)                         |
| `-h`, `--help`          | Afficher l'aide et quitter (sans sudo)                             |

---

## Fichiers

| Fichier                                  | Description                                                              |
|------------------------------------------|--------------------------------------------------------------------------|
| `~/.local/bin/bob`                 | Point d'entrée pipx                                                      |
| `/usr/local/bin/bob`               | Lien symbolique pour l'accès sudo (créé par `--install-completion`)      |
| `/etc/bash_completion.d/bob`       | Autocomplétion bash (créée par `--install-completion`)                   |
| `/usr/local/bin/bob-nightly`       | Script wrapper nocturne (créé par `--install-cron`)                      |
| `/etc/cron.d/bob-{nom}`            | Entrée cron nommée (créée par `--install-cron`)                          |
| `~/.config/bob/config.conf`        | Configuration utilisateur (ports personnalisés, répertoire logs ; 600)   |
| `~/.config/bob/services.d/*.json`  | Répertoire de plugins — définitions de services personnalisés (voir note) |
| `bob_YYYYMMDD_HHMMSS.log`          | Rapport détaillé (créé avec `-d`, dans le répertoire configuré)          |

> **Répertoire de plugins et `sudo` :** depuis v0.3.6 BOB résout `~/.config/bob/` vers le home
> de l'utilisateur invoquant (via `SUDO_USER`), donc les plugins déposés dans `/home/<vous>/.config/bob/services.d/`
> sont correctement chargés sous `sudo bob`. Les fichiers écrits par BOB sous sudo sont automatiquement chownés vers l'utilisateur.
>
> **Forme des fichiers plugins :** chaque fichier `*.json` est un tableau JSON d'objets service.
> Le contrat formel est publié comme `bob/data/schemas/service.schema.json` (JSON Schema Draft 2020-12)
> et `bob/data/schemas/services-list.schema.json` pour le wrapper tableau. Voir "Schéma de plugin de service" ci-dessous.
>
> **Futur paquet `.deb` :** le répertoire système `/etc/bob/services.d/` sera ajouté comme chemin
> de chargement additionnel (sans supprimer celui per-user) pour la convention Debian standard.

### Schéma de plugin de service

Les définitions de services sont validées contre `bob/data/schemas/service.schema.json` (Draft 2020-12, livré avec le paquet). Les deux `services.json` bundled et les plugins utilisateur suivent la même forme par entrée :

```json
{
  "id":         "myservice",
  "label":      "My Service",
  "packages":   ["mypackage"],
  "services":   ["myservice"],
  "ports":      ["8080/tcp"],
  "risk":       "medium",
  "config_key": "fixed",
  "detection": {
    "binary":       ["/usr/local/bin/myapp"],
    "snap":         ["myapp-snap"],
    "config_files": ["/etc/myapp/config.yml"]
  }
}
```

**Champs obligatoires :** `id`, `label`, `packages`, `services`, `ports`, `risk`, `config_key`. **Optionnel :** `detection`. `risk` ∈ `{"low", "medium", "high", "critical"}`. `config_key` vaut `"fixed"`, `"ask"`, `"auto"`, ou un identifier Python. **Plage de port 1–65535** (stricte).

**Contraintes métier appliquées par le schéma :**

- `config_key="fixed"` requiert au moins un port.
- `config_key="auto"` requiert `detection.config_files` non-vide (l'auto-resolver a besoin de fichiers à parser).
- Un service doit être détectable : au moins un parmi `packages`, `services`, ou `detection.{binary|snap}` doit être non-vide.
- Un bloc `detection: {}` vide est rejeté (n'apporte aucun signal).

**Forme du fichier plugin.** Un fichier plugin utilisateur sous `~/.config/bob/services.d/*.json` peut utiliser l'une des deux formes équivalentes :

1. **Tableau brut** (legacy / défaut actuel) — un tableau JSON nu d'objets service.
2. **Objet wrappé** (forward-compat) — `{"schema_version": 1, "services": [ ... ]}`. Le wrapper existe pour que les futures migrations de schéma puissent être gatées explicitement via `schema_version`. Seul `schema_version: 1` est accepté aujourd'hui ; les champs réservés comme `metadata`, `disabled` sont marqués pour les versions futures.

Voir `bob/data/schemas/plugin-file.schema.json` pour le méta-schéma du wrapper. Valider en externe avec n'importe quel outil JSON Schema 2020-12 (e.g. `check-jsonschema`, `ajv`).

**Scope du schéma.** Le schéma valide la structure et la forme syntaxique. Il **n'applique pas** : l'unicité cross-service de `id` (check runtime) et l'exclusion des reserved keywords Python pour `config_key` (check runtime). Un document conforme au schéma peut quand même être rejeté au chargement si ces invariants runtime sont violés — la source de vérité canonique reste `bob.registry.Service.from_dict()`.

---

## Codes de retour

> **API publique stable** — ces codes font partie du contrat de BOB. Ils ne changeront pas au sein d'une version majeure (pas de suppression, pas de glissement sémantique). De nouveaux codes pourront être ajoutés en fin de liste si nécessaire.

En mode `--quiet`, le code de retour indique le résultat de l'audit :

| Code | Constante | Signification |
|------|-----------|---------------|
| `0`  | `EXIT_OK`            | Audit propre — aucune alerte, aucun avertissement |
| `1`  | `EXIT_WARNINGS`      | Avertissements détectés (améliorations suggérées) |
| `2`  | `EXIT_ALERTS`        | Alertes détectées — action requise |
| `3`  | `EXIT_ERROR`         | Erreur technique (parsing CLI, IO, interne) |
| `4`  | `EXIT_TARGET_MISSED` | `--target N` spécifié et score < N |

Les constantes sont exposées dans `bob.__main__` pour un usage programmatique :

```python
from bob.__main__ import EXIT_OK, EXIT_WARNINGS, EXIT_ALERTS, EXIT_ERROR, EXIT_TARGET_MISSED
```

Exemple cron — audit quotidien à 6h, mail en cas de problème :

```bash
0 6 * * * sudo bob --quiet -d || echo "bob exit $? on $(hostname)" | mail -s "UFW Alert" admin@example.com
```

---

## Schéma de sortie JSON

> **API publique stable** — la structure produite par `--json` / `--json-full` (ou `--format=json`) fait partie du contrat de BOB. Règles de rétrocompatibilité :
>
> - Les clés top-level ne disparaissent jamais, ne sont jamais renommées, ne changent jamais de sémantique au sein d'une même version majeure de `schema_version`.
> - De nouvelles clés top-level PEUVENT être ajoutées dans n'importe quelle release ; les clients doivent ignorer les clés inconnues.
> - Les dicts imbriqués suivent la même règle (ajouts OK, suppressions/renommages = breaking).
> - Les changements breaking incrémentent `schema_version` à un nouveau majeur (`"2"`, `"3"`…).

### Clés top-level (toujours présentes)

| Clé | Type | Description |
|---|---|---|
| `schema_version` | string | Version majeure du schéma (actuellement `"1"`) |
| `version` | string | Version de BOB qui produit la sortie |
| `host` | string | Nom d'hôte (`uname -n`) |
| `timestamp` | string | Timestamp UTC ISO 8601 |
| `score` | int (0–10) | Score de sécurité global |
| `score_max` | int | Toujours `10` |
| `risk` | string | Niveau de risque : `"low"`, `"medium"`, `"high"`, `"critical"` |
| `network_context` | string | `"local"`, `"private"`, ou `"public"` |
| `public_ip` | string | IP publique (vide derrière NAT) |
| `alerts` | int | Nombre de findings ALERT |
| `warnings` | int | Nombre de findings WARN |
| `deductions` | array | Déductions de score (voir ci-dessous) |
| `domain_scores` | object | Sous-scores par domaine (voir ci-dessous) |

### Structure `deductions[]`

```json
{ "reason": "Journalisation UFW désactivée", "points": 2, "key": "firewall.logging_off" }
```

Le champ `key` est une **clé i18n stable en notation pointée** (`<domaine>.<finding>`) — c'est sur ce champ qu'il faut matcher (et non sur `reason` localisée) pour une logique cliente stable entre locales.

### Structure `domain_scores`

```json
{
  "ssh":        { "score": 7,  "label": "SSH" },
  "samba":      { "score": 10, "label": "Samba Security" },
  "file_perms": { "score": 10, "label": "Files & Access" },
  "updates":    { "score": 10, "label": "Updates" },
  "hardening":  { "score": 6,  "label": "Hardening" },
  "disk":       { "score": 9,  "label": "Disk Health" },
  "firewall":   { "score": 10, "label": "Firewall & Services" }
}
```

Les clés de domaines sont stables : `ssh`, `samba`, `file_perms`, `updates`, `hardening`, `disk`, `firewall` (7 au total — définies dans `bob.domain_scores.DOMAINS`). Chaque entrée a `score` (int 0–10), `label` (nom d'affichage anglais), et `deductions` (total des points déduits dans ce domaine).

### Clés additionnelles en mode complet (`--json-full`)

| Clé | Type | Description |
|---|---|---|
| `findings` | array | Tous les findings avec `{ key, level, message, nature, cmd, note }` |
| `services` | array | Services réseau installés avec `{ name, installed, active, risk, ports }` |
| `open_ports` | array | Ports en écoute sur `0.0.0.0` avec `{ port, address, process }` |
| `firewall_stack` | object | Détection bypass UFW : docker, libvirt, nftables, ip_forward, etc. |
| `hardening` | object | Flags sysctl/AppArmor (uniquement quand collectés) |
| `ipv6` | object | Cohérence pile IPv6 (uniquement quand collectées) |

### Exemple de matching stable (indépendant de la locale)

```bash
# Matcher un finding spécifique par clé, indépendamment de la locale
sudo bob --json | jq '.deductions[] | select(.key == "firewall.logging_off")'
```

Les `findings[*].key` et `deductions[*].key` font partie du jeu de clés `--explain` — elles ne changeront pas sans bump majeur du schéma.

---

## Politique de support Python

> **Engagement public stable** — ces règles régissent quand BOB abandonne le support d'un ancien Python.

BOB supporte les versions Python **N et N-2**, où **N** est la stable upstream actuelle. À partir de v0.5.5 :

| Python | Statut |
|---|---|
| 3.13 | ✅ supporté (à la sortie — à tester) |
| 3.12 | ✅ supporté (cible de développement actuelle, CI par défaut) |
| 3.11 | ✅ supporté |
| 3.10 | ✅ supporté (le plus ancien actuellement supporté) |
| 3.9  | ❌ end of life (abandonné en v0.2.3) |

Quand Python 3.14 sortira upstream (~fin 2025), Python 3.10 entrera en fenêtre de dépréciation :
- **+ 1 release minor BOB** avec 3.10 et 3.14 en CI pour valider.
- **+ 1 release minor BOB** annonçant la dépréciation 3.10 dans le changelog et `--help`.
- **+ 1 release minor BOB** retire 3.10 de la CI et bump `python_requires` dans `pyproject.toml`.

L'intention : au moins 6 mois de préavis avant tout abandon, miroir des gels distros (Debian stable etc.). Les packagers peuvent compter sur cette politique pour planifier leurs rebuilds.

## Packaging (depuis v0.4.2)

Le dépôt livre tout ce qu'il faut à un mainteneur distro pour packager BOB :

- **`man/bob.1`, `man/bob.conf.5`, `man/bob-profile.5`** — pages de manuel.
- **`SECURITY.md`** — threat model + politique de disclosure de vulnérabilités.
- **`debian/`** — paquet source Debian (3 binaires : `bob-core`, `bob-tui`, `bob` meta-package). Testé avec `debhelper-compat (= 13)` et `pybuild-plugin-pyproject`. Cible lintian-clean (un override info-level possible sur `binary-without-manpage` pour le meta-package `bob` qui n'a pas d'exécutable propre).
- **`debian/apparmor.d/bob`** — profil AppArmor (livré en mode `complain` par défaut, `enforce` opt-in).
- **`packaging/rpm/bob.spec`** — spec RPM Fedora / RHEL bâti sur `pyproject-rpm-macros`. Ciblé Fedora COPR pour la distribution initiale.

Contributions packaging bienvenues — voir `SECURITY.md` pour le processus de disclosure si vous trouvez un problème sécurité dans le packaging lui-même.

---

## Précision importante

BOB est un outil d'audit et de diagnostic, pas un bouclier de sécurité. Il analyse votre configuration et vous signale les problèmes — mais il ne les corrige pas automatiquement sans votre accord, et il ne peut pas tout détecter. Certains logiciels comme Docker peuvent contourner UFW en manipulant directement iptables : bob détecte ce cas spécifique et vous le signale, mais il existe d'autres vecteurs similaires qui sortent du périmètre actuel du projet. En résumé : bob vous aide à voir plus clair, il ne se substitue pas à une bonne hygiène de sécurité générale.

---

## Licence

MIT License — © 2026 Cédric Clauzel. Voir `LICENSE` pour les détails.

---

## Auteur

Cédric Clauzel

---

© 2026 Cédric Clauzel
