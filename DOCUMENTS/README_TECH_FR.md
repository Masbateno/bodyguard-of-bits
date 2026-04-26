*[Read in English](README_TECH.md)* · *[Vue d'ensemble](../README_FR.md)*

# BOB — Bodyguard Of Bits

![License](https://img.shields.io/badge/license-MIT-green)
![Release](https://img.shields.io/badge/version-v0.1.0-brightgreen)
![CI](https://github.com/Masbateno/bodyguard-of-bits/actions/workflows/tests.yml/badge.svg)
![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu%20%7C%20Mint-informational)
![Language](https://img.shields.io/badge/language-Python%203.9%2B-yellow)

Auditeur de durcissement Linux pour les admins système et power users. Mapping des benchmarks CIS, 46 vérifications sur 9 domaines, explications en langage clair et commandes de correction prêtes à l'emploi.

BOB analyse votre configuration UFW, détecte les services réseau exposés, classe les risques par service, et fournit des explications en langage clair avec des commandes de correction prêtes à l'emploi.

---

## Fonctionnalités

- **Bannière ASCII** avec informations système (distro, hôte, version UFW, utilisateur, date)
- **Vérification du statut UFW** — actif/inactif, politique par défaut entrante
- **Analyse des règles UFW** — règles en doublon, `allow from any` sans restriction de port, cohérence IPv6
- **Score contextuel** — détection du contexte réseau (IP publique directe vs NAT) ; pénalités doublées sur les machines exposées sur internet ; pare-feu inactif plafonne le score à 3/10
- **Détection de 32 services réseau courants** avec analyse de leur exposition UFW et contexte de risque à deux axes (exposition + menace) pour les services critiques et élevés ; services CRITICAL/HIGH installés mais inactifs émettent ⚠ + bloc de contexte de risque
- **Audit iptables/nftables** — quand UFW est inactif, audite la couche pare-feu sous-jacente : détecte le backend actif (iptables vs nftables) ; vérifie les politiques par défaut INPUT et FORWARD ; contrôle la présence du suivi de connexion conntrack ; ⚠ −1 pt par politique permissive ; conditionné sur `not fw_status.active`
- **Docker** — détection du contournement iptables et liste des ports exposés par les containers en cours d'exécution
- **Virtualisation** — détecte les hyperviseurs actifs (libvirt/KVM, VirtualBox, VMware, LXD/LXC) et les paquets Snap réseau qui peuvent créer des interfaces bridge et manipuler iptables directement, contournant UFW — même risque que Docker
- **Ports en écoute** — passe unique unifiée ; ports éphémères et système ignorés proprement ; NetBIOS géré avec avertissement contextuel
- **Logs UFW** — parse `/var/log/ufw.log` sur une période configurable (`--log-days=N`, défaut 7 jours) ; total des tentatives bloquées, top IPs sources avec géolocalisation, top ports ciblés, détection bruteforce (>10 tentatives/60s), tentatives sur les ports de services installés
- **Géolocalisation IP** — IPs sources enrichies avec pays et opérateur via GeoIP2 (optionnel, `python3-geoip2` + base GeoLite2) ; plages privées identifiées comme réseau local ; résultats mis en cache par session
- **Détection DDNS / exposition externe** — détecte les clients DDNS actifs (ddclient, inadyn, No-IP, DuckDNS) ; extrait le domaine configuré ; croise avec les règles UFW ALLOW sans restriction pour identifier les ports exposés sur internet
- **Classification d'exposition** par service : `ouvert sur internet` / `réseau local uniquement` / `bloqué par UFW` / `pas de règle`
- **Mode fix** — section interactive après le résumé ; chaque correction automatisable demande une confirmation `[y/N]` ; éléments manuels affichés sans exécution ; `-y / --yes` applique tout sans confirmation avec une bannière d'avertissement et un résumé des commandes exécutées
- **Résumé catégorisé** — findings répartis en trois blocs : *Action requise* / *Améliorations possibles* / *Configuration normale* ; phrase d'interprétation automatique
- **Note de politique implicite** — signale quand des services à risque élevé s'appuient sur la politique `deny` par défaut plutôt que sur des règles explicites
- **Score de sécurité** (0–10) avec niveau de risque : FAIBLE / MOYEN / ÉLEVÉ / CRITIQUE
- **Panorama des services** — tableau compact de l'ensemble des 32 services connus après l'audit services (SERVICE / STATUT / PORT(S) / UFW), services non installés affichés en grisé
- **Interface bilingue** — anglais par défaut, français avec `--french`
- **Mode sans couleur** — `--no-color` pour une sortie propre dans les pipes et fichiers log
- **Rapport détaillé optionnel** — fichier log horodaté avec en-tête ASCII art, informations système, findings et recommandations
- **`--manage-logs`** — interface interactive pour lister les rapports sauvegardés (nom, taille, date) et les supprimer par index ou en totalité ; Entrée ouvre un visualiseur de log scrollable (`s` bascule mode complet/résumé ; `g`/`G` haut/bas)
- **`--install-cron`** — wizard de planification : nommer le cron, choisir le type de schedule (tous les jours / certains jours de la semaine / certains jours du mois / expression cron personnalisée), définir l'heure et un email de notification optionnel ; aperçu en langage naturel avant confirmation ; crons nommés (`/etc/cron.d/bob-{nom}`)
- **`--manage-cron`** — TUI en boucle : lister les crons installés, modifier le planning ou l'email de notification, supprimer ; la commande `m` ouvre le carnet d'adresses email (ajout / suppression d'adresses enregistrées), accessible même sans cron installé
- **Vérification durcissement** — audit du durcissement système : unattended-upgrades, mode AppArmor, rp_filter, redirections ICMP, log_martians, broadcast ICMP ; déductions scorées pour les paramètres les plus impactants
- **Cohérence IPv6** — détecte les ports IPv6 actifs sans règle UFW v6 correspondante ; détection de conflit quand IPv6 est désactivé globalement mais des ports en écoute sont présents
- **Rapport comparatif** — baseline enregistrée après chaque audit (`~/.config/bob/last_baseline.json`) ; au prochain lancement, affiche le delta de score, les variations d'alertes/avertissements, les ports apparus/fermés, les services démarrés/arrêtés
- **API Plugin** — déposer un fichier Python dans `~/.config/bob/checks.d/` pour ajouter une vérification personnalisée ; les plugins sont fail-safe (les exceptions n'interrompent jamais l'audit) et les séquences ANSI sont nettoyées
- **Audit de sécurité SSH** — analyse complète de `sshd_config` (15 directives + Ciphers/MACs/KEX faibles) ; audit des clés privées (type, taille, passphrase) ; inspection `authorized_keys` ; vérification côté client `~/.ssh/config` ; comptage des entrées `known_hosts` ; cible le home de `SUDO_USER` ; suggestions d'installation adaptées à la distro
- **Fichiers sensibles & sudoers** — audit des permissions de `/etc/passwd`, `/etc/shadow`, `/etc/gshadow`, `/etc/group`, `/etc/sudoers` (modifiable par tous → ALERT, trop permissif → WARN) ; permissions des clés hôtes privées SSH sous `/etc/ssh/` ; détection de `NOPASSWD:ALL` dans sudoers et sudoers.d
- **Audit des mises à jour système** — détecte les paquets de sécurité en attente via `apt-get -s upgrade` (−2 pts fixe) ; absence de `unattended-upgrades` combinée à des mises à jour de sécurité en attente (−1 pt composé) ; mises à jour régulières → INFO uniquement
- **Détection d'applications de bureau** — détecte les applications GUI connues (Steam, Discord, Zoom, Signal, VLC, Spotify, Slack, Telegram, Chrome, Firefox…) en cours d'exécution ; findings INFO, sans déduction ; section affichée uniquement si au moins une appli est détectée
- **Synchronisation NTP** — vérifie si systemd-timesyncd, chronyd ou ntpd est actif et synchronisé ; WARN −1 pt si NTP est désactivé ou l'horloge pas encore synchronisée
- **Prévention d'intrusion Fail2ban** — check autonome dédié ; détecte l'installation, l'état du service, les jails actifs et la présence d'un jail SSH ; WARN −1 pt si service inactif ou aucun jail configuré
- **Scan rootkit & intégrité** — détection rkhunter/chkrootkit ; WARN −1 pt pour base de données rkhunter obsolète (≥7 jours), scan absent ou dernier scan trop ancien (>30 jours)
- **Linux Audit Framework (auditd)** — détecte l'installation, l'état du service, les règles chargées et la couverture des fichiers sensibles (/etc/passwd, /etc/shadow, /etc/sudoers) ; WARN −1 pt chacun pour service inactif, aucune règle, fichiers non couverts (profil server uniquement)
- **Secure Boot** — état UEFI via `mokutil --sb-state` → `/sys/firmware/efi/efivars/` → `bootctl status` ; WARN −1 pt si désactivé sur desktop ; INFO si désactivé sur server/VM ou BIOS/inconnu
- **Intégrité des fichiers (AIDE/Tripwire)** — détecte l'installation, l'initialisation de la base et la date du dernier check ; AIDE préféré à Tripwire ; WARN −1 pt si base absente ou check absent/trop ancien (>30 jours)
- **`--explain KEY`** — explication structurée par constat (POURQUOI C'EST UN RISQUE / COMMENT CORRIGER / référence CIS Ubuntu 22.04) ; 112 clés explicables dans 26 groupes ; 17 clés affichent des sections par profil (`[ server ]` / `[ desktop ]` / `[ container ]`) ; note uniforme jaune pour les clés sans différence entre profils ; TUI interactif avec délai ESC réduit à 25 ms ; sans droit root
- **Scores par domaine** — sous-scores de sécurité par domaine (SSH / Sécurité Samba / Fichiers & Accès / Mises à jour / Durcissement / Santé Disque / Pare-feu & Services) ; 7 domaines ; affichés en barre █/░ après l'audit ; inclus dans la sortie JSON et le payload webhook
- **Webhooks** — `--webhook URL` envoie le résultat d'audit en JSON après chaque audit ; formats générique (Grafana/automation) et Slack (auto-détecté) ; non-fatal ; `--webhook-format=auto|generic|slack`
- **Mode `--diff`** — lance l'audit silencieusement et affiche uniquement le delta comparatif (changements depuis le dernier audit) ; suit le score, le nombre d'alertes/avertissements et le nombre d'INFO (les changements de niveau INFO sont donc détectés)
- **Audit sécurité Samba** — analyse complète de `smb.conf` : détection protocole SMB1 (ALERT, −2 pts) ; mots de passe nuls activés (ALERT, −3 pts) ; signature serveur désactivée (WARN, −1 pt) ; partages accessibles en écriture par l'invité (ALERT, −2 pts/partage) ; partages lisibles par l'invité (WARN, −1 pt/partage) ; `map to guest = bad user` (WARN, −1 pt) ; vérification bind interfaces (INFO) ; domaine **samba** dédié
- **Audit antivirus ClamAV** — détection installation (`clamscan`/`clamdscan`/`freshclam`) ; fraîcheur de la base de données virus via mtime (WARN −1 pt > 7 jours, ALERT −2 pts > 30 jours) ; statut démon clamd avec repli sur le fichier socket pour les containers ; date du dernier scan parsée depuis les chemins de logs standards (WARN −1 pt > 30 jours, −1 pt > 90 jours) ; déductions routées vers le domaine **hardening**
- **Dominance source locale IoT** — détecte quand une seule IP privée représente ≥ 70 % du trafic UFW bloqué sur ≥ 50 entrées de log (WARN, −1 pt, `logs.local_dominance`) ; typique des appareils IoT qui scannent le LAN ou des serveurs mal configurés
- **Exposition SMTP locale** — détecte les MTA (Postfix, Exim, Sendmail) en écoute sur toutes les interfaces (`0.0.0.0:25` ou `:::25`) vs localhost uniquement ; `SmtpSnapshot.from_system()` utilise `ps -eo comm` + `ss -tlnp`/repli `netstat` ; WARN −1 pt si exposition publique
- **`--fix` aperçu par défaut** — `--fix` seul affiche un aperçu de toutes les corrections disponibles avec `→ cmd` sans exécuter ; `--fix --apply` active le flux d'application interactif ; `--fix --apply --yes` confirme tout automatiquement avec journal d'audit
- **`--target N`** — objectif de score (1–10) ; affiché dans la boîte de synthèse comme `✔ atteint` (vert) ou `▲ +N pt(s) manquant(s)` (jaune) ; retourne le code de sortie 4 si le score < cible (intégration CI, prioritaire sur les codes 1/2)
- **5 en-têtes de groupes thématiques** — sortie de l'audit réorganisée en cinq groupes nommés : FIREWALL & RÉSEAU / EXPOSITION & SERVICES / CONTRÔLE D'ACCÈS / DURCISSEMENT SYSTÈME / DÉTECTION & SANTÉ ; chaque groupe introduit par un séparateur `━` cyan pleine largeur avec le titre centré
- **`cmd_type` sur les findings** — `Finding` gagne `cmd_type: str = "fix"` / `"check"` ; la boîte de synthèse utilise `→` pour les commandes de correction et `ℹ` pour les commandes de vérification
- **Profils d'audit** — `server` (défaut), `desktop` (remplace `workstation`), `container` ; alias `workstation` conservé ; profil actif affiché dans la boîte de synthèse
- **Contrôle niveau de journalisation UFW** — détecte le niveau UFW (`ufw status verbose`) ; `off` → ALERT −2 pts (aucune visibilité sur le trafic bloqué) ; `low`/`medium` → OK ; `high`/`full` → INFO (mode verbeux, sans déduction)
- **Audit umask système** — `UmaskSnapshot` lit le umask depuis `/etc/login.defs`, PAM, `/etc/profile`, RC shells et processus courant ; umask permissif (0002/0000) → WARN −1 pt ; sources conflictuelles → WARN −1 pt ; `_fix_cmd()` propose `/etc/profile.d/umask.conf`
- **Analyse auth.log SSH** — `AuthLogSnapshot` parse `/var/log/auth.log` ; détection brute-force (>10 tentatives échouées depuis la même IP en 60 s → ALERT −2 pts) ; dernières connexions réussies affichées ; top sources d'échec listées ; `days=0` (log vide/rotaté) géré avec clé dédiée sans interpolation de zéro
- **Historique des scores** — JSONL dans `~/.config/bob/history.jsonl` ; `--history` affiche les N derniers scores sous forme de sparkline (▁▂▃▄▅▆▇█) avec dates ; rotation automatique à 90 entrées
- **Liste d'exceptions (ignore)** — `--ignore KEY` ajoute une clé de finding dans `ignore.yml` ; `--show-ignored` liste toutes les exceptions ; `ScoreEngine.ignore_keys` frozenset masque les findings correspondants sans les scorer ; indice affiché dans la sortie ; `{check_key}` utilisé dans la locale pour éviter le conflit de signature de `t()`
- **Classification process-aware des ports système** — frozenset `_SYSTEM_DAEMONS` dans `checks/ports.py` ; les ports de `_SYSTEM_PORTS` (DNS, DHCP, mDNS, UPnP…) ne sont classés `SYSTEM_INTERNAL` que si l'application propriétaire est un démon OS connu ; les apps utilisateur (ex. Spotify sur `1900/udp`) passent aux vérifications d'exposition normales
- **Audit expiration certificats TLS/SSL** — analyse Let's Encrypt (`/etc/letsencrypt/live/*/fullchain.pem`), `/etc/ssl/private/*.{pem,crt,cert}`, directives nginx `ssl_certificate`, `SSLCertificateFile` apache2, `smtpd_tls_cert_file` postfix ; expiré → ALERT −2 pts ; <7 j → ALERT −2 pts ; <30 j → WARN −1 pt ; total plafonné à −4 pts ; `_MAX_CERTS=30` ; chemins entre guillemets et liens symboliques cassés gérés
- **Audit sécurité timers systemd** — `systemctl list-timers --all --no-pager` ; curl/wget pipé vers un shell dans ExecStart → WARN −2 pts (flat) ; scripts `.sh` world-writable dans ExecStart → WARN −1 pt (flat) ; timers créés par l'utilisateur dans `/etc/systemd/system/` sans `User=` → INFO ; deux regex indépendantes prévient les faux négatifs sur `/bin/bash`/`bash -c` ; `lstrip("-@")` gère les préfixes systemd ; `_MAX_TIMERS=100`
- **Audit firmware & microcode** — `fwupdmgr get-updates` (cache, sans réseau forcé) ; firmware device en attente → WARN −1 pt ; paquet microcode CPU via `dpkg -l` ; Intel → `intel-microcode` ; AMD → `amd64-microcode` ; non Intel/AMD → INFO ; absent → WARN −1 pt ; correspondance exacte par colonne pour les paquets qualifiés par architecture ; résultats erreur et mises à jour découplés
- **Export HTML `--html`** — `build_html_output()` produit un fichier HTML autosuffisant (sans JS, sans ressources externes) ; CSS embarqué ; cercle de score coloré ; badges ALERT/WARN/INFO/OK ; tableau déductions ; `_h()` applique `html.escape(quote=True)` à toutes les données utilisateur — protection XSS
- **`--check LIST` / `--skip LIST`** — n'exécuter que les checks nommés (`--check=ssh,firewall`) ou les exclure (`--skip=clamav,rootkit`) ; mutuellement exclusifs ; helper `_section_enabled()` dans `runner.py` ; `validate_check_filters()` avertit sur les noms inconnus ; `skip_sections` du profil respecté ; `--check=list` affiche les 31 noms de sections filtrables (sans sudo)
- **`--output-dir PATH`** — surcharger le répertoire de sauvegarde du rapport pour l'exécution courante ; `get_or_prompt_log_dir()` priorise ce paramètre sur la config sauvegardée ; sans persistance
- **Moteur de corrélation de signaux** — `correlation.py` : 5 règles de risque composé (root+sans-fail2ban → ALERT ; auth-mot-de-passe+brute-force → ALERT ; root+password → ALERT ; NOPASSWD+SUID → WARN ; stale+sans-fail2ban → WARN ; logging-off+sans-fail2ban+sans-auditd → WARN) ; `CorrelationRule` avec frozensets `all_of`/`any_of` ; évalué post-finalize sur les clés ALERT+WARN ; liste `triggered_by` identifie les findings déclencheurs
- **Suivi des findings récurrents** — `recurrence.py` : compteur d'apparitions consécutives par clé ALERT/WARN ; `~/.config/bob/recurrence.json` ; écriture atomique ; valeurs corrompues/négatives normalisées ; clés vides filtrées au chargement
- **Analyse d'exposition des ports** — `exposure.py` : regroupe les services en écoute exposés par portée d'interface et niveau de risque ; allowlist `fw_policy not in ("deny", "reject")` ; attribut direct `lp.port` pour le filtre ports éphémères
- **Rapport comparatif — diff de clés de findings** — `AuditBaseline.finding_keys` persiste les clés ALERT+WARN actives ; `AuditDelta` ajoute `new_finding_keys` / `resolved_finding_keys` ; garde de migration contre le flood de faux positifs à la première exécution après mise à jour ; `display_delta()` affiche chaque clé apparue/résolue
- **Correctif faux positif IPv6 link-local** — parseur `_read_global_ipv6()` ; champ `has_global_ipv6` ; WARN −2 pts rétrogradé en INFO quand seules des adresses link-local (fe80::/10) ou ULA (fc/fd::/7) sont assignées — machine non joignable via IPv6 depuis internet
- **Correctif message noyaux obsolètes** — clé locale `kernels_obsolete_same` ; supprime la parenthèse redondante "(actif : X, récent : X)" quand le noyau actif est identique au plus récent installé
- **Filtre certificat snakeoil** — `ssl-cert-snakeoil.pem` exclu du scan `/etc/ssl/private` ; empêche le certificat de test Debian/Ubuntu de déclencher l'audit TLS
- **`--explain`** — 87→112 clés (+25 sur 7 nouveaux groupes : Journaux d'authentification, Umask, Journalisation du pare-feu, Certificats TLS/SSL, Timers Systemd, Firmware, Docker)
- **`--format=FORMAT`** — flag de sortie unifié : `json | json-full | csv | markdown | html` ; anciens flags (`-j`, `-J`, `--output csv`, `--html`) conservés comme aliases silencieux ; mutuellement exclusifs entre eux
- **`--check=list`** — affiche les 31 noms de sections filtrables avec une note sur la correspondance par préfixe ; sans sudo
- **TUI curses `--install-cron`** — `run_install_cron()` enveloppe `curses.wrapper()` avec readline intégré, Esc-pour-annuler sur chaque prompt, aperçu live du planning ; repli sur le wizard texte si curses indisponible ; `run_manage_cron()` amélioré de la même façon
- **`bob/_tty.py`** — lecteur ligne mode raw (`read_line()`) : Échap standalone retourne `None` (annuler) ; séquences de touches directionnelles drainées via `select` 50 ms ; repli `input()` en non-TTY (tests, pipes)
- **Qualificateur de portée du contexte de risque** — `[CRITIQUE • LAN]` (ou `[CRITICAL • LAN]` en anglais) ajouté aux labels de service quand le contexte réseau est local ; évite la confusion entre risque local et exposition internet
- **Harmonisation barres d'aide TUI** — hints cohérents dans `--explain`, `--manage-logs` et prévisualisation de log : `↑↓: move` pour la navigation, `↑↓ / PgUp/PgDn: scroll` pour le contenu, `Esc: back` pour les sous-écrans
- **Cartographie CIS inline** — chaque finding dans la boîte de synthèse affiche son code CIS `[CIS:X.Y.Z]` (estompé) ; ref CIS complète affichée estompée en `--verbose` après chaque finding WARN/ALERT ; refs servies depuis `cis_refs.json` (133 entrées : 99 CIS formels, 34 best-practice, 4 Docker), indépendantes de la langue ; API publique `get_cis_ref()` / `get_cis_code()`
- **5 nouveaux services (v0.1.0)** — SMTP/Postfix (25/tcp, élevé), NFS Server (2049/tcp+udp, élevé), Jenkins (8080/tcp, élevé), OpenVPN (1194/udp, moyen), Squid Proxy (3128/tcp, moyen) ; le registre couvre désormais 32 services

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

- Système Linux — Debian, Ubuntu, Linux Mint, ou dérivé
- UFW installé : `sudo apt install ufw`
- Python 3.9+
- `ss` recommandé (paquet `iproute2`) — disponible par défaut sur les systèmes modernes
- `python3-geoip2` + base GeoLite2 recommandés pour la géolocalisation IP (optionnel) : `sudo apt install python3-geoip2 geoip-database`
- `docker` CLI pour l'analyse Docker (optionnel)

---

## Installation

### Prérequis

- Système Linux — Debian, Ubuntu, Linux Mint, ou dérivé
- UFW installé : `sudo apt install ufw`
- pipx : `sudo apt install pipx && pipx ensurepath`

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
║  BOB v0.1.0  │  Auditeur de durcissement Linux                               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  System        : Ubuntu 24.04 LTS                                            ║
║  Host          : my-machine                                                  ║
║  UFW           : v0.36.2                                                     ║
║  User          : alice                                                       ║
║  Date          : 27/03/2026 10:00                                            ║
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
bob_20260323_100000.log
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

> **Répertoire de plugins et `sudo` :** bob s'exécute en root. Sous `sudo`, `Path.home()` retourne `/root`,
> donc le répertoire de plugins actif est `/root/.config/bob/services.d/`, et non le home de l'utilisateur appelant.
> Placez vos fichiers de plugins à cet emplacement pour qu'ils soient chargés à l'exécution.
>
> **Futur paquet `.deb` :** ce comportement changera au profit du répertoire système `/etc/bob/services.d/`,
> conformément à la convention Debian et pour éliminer l'ambiguïté liée à `sudo`/home.

---

## Codes de retour

En mode `--quiet`, le code de retour indique le résultat de l'audit :

| Code | Signification |
|------|---------------|
| `0`  | Audit propre — aucune alerte, aucun avertissement |
| `1`  | Avertissements détectés |
| `2`  | Alertes détectées — action requise |
| `3`  | Erreur technique |
| `4`  | Score inférieur au seuil `--target N` |

Exemple cron — audit quotidien à 6h, mail en cas de problème :

```bash
0 6 * * * sudo bob --quiet -d || echo "bob exit $? on $(hostname)" | mail -s "UFW Alert" admin@example.com
```

---

## Précision importante

BOB est un outil d'audit et de diagnostic, pas un bouclier de sécurité. Il analyse votre configuration et vous signale les problèmes — mais il ne les corrige pas automatiquement sans votre accord, et il ne peut pas tout détecter. Certains logiciels comme Docker peuvent contourner UFW en manipulant directement iptables : bob détecte ce cas spécifique et vous le signale, mais il existe d'autres vecteurs similaires qui sortent du périmètre actuel du projet. En résumé : bob vous aide à voir plus clair, il ne se substitue pas à une bonne hygiène de sécurité générale.

---

## Licence

MIT License — © 2026 Cédric Clauzel. Voir `LICENSE` pour les détails.

---

## Auteur

Cédric Clauzel
