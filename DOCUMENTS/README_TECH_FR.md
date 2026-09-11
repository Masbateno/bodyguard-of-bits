<p align="center">
  <img src="https://raw.githubusercontent.com/Masbateno/bodyguard-of-bits/main/assets/logo_bob.png" alt="BOB — Bodyguard Of Bits" width="180">
</p>

*[Read in English](README_TECH.md)* · *[Vue d'ensemble](../README_FR.md)*

# BOB — Bodyguard Of Bits

![License](https://img.shields.io/badge/license-MIT-green)
![Release](https://img.shields.io/badge/version-v0.18.1-brightgreen)
![PyPI](https://img.shields.io/pypi/v/bodyguard-of-bits?label=pypi&color=blue)
![Downloads](https://img.shields.io/pypi/dm/bodyguard-of-bits?label=downloads&color=blue)
![CI](https://github.com/Masbateno/bodyguard-of-bits/actions/workflows/tests.yml/badge.svg)
![Integration](https://github.com/Masbateno/bodyguard-of-bits/actions/workflows/integration.yml/badge.svg)
![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)
![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu%20%7C%20Mint%20%7C%20Kali%20%7C%20Fedora%20%7C%20Arch%20%7C%20openSUSE%20%7C%20Alpine%20%7C%20Raspberry%20Pi-informational)
![Python](https://img.shields.io/pypi/pyversions/bodyguard-of-bits)

BOB est un auditeur de durcissement Linux pour les admins système et power users. Il exécute 39 sections de vérification sur 7 domaines de score, mappe les résultats aux benchmarks CIS quand applicable, et fournit des explications claires avec des commandes de correction prêtes à l'emploi.

---

## Fonctionnalités

### Audit principal

- **Bannière ASCII** avec informations système — distro, hôte, version UFW, utilisateur, date
- **Vérification du statut UFW** — actif/inactif, politique par défaut entrante
- **Analyse des règles UFW** — règles en doublon, `allow from any` sans restriction de port, cohérence IPv6
- **Score contextuel** — détection du contexte réseau (IP publique directe vs NAT) ; pénalités plus lourdes sur les machines exposées sur internet (un port ouvert non couvert passe de 1 à 2 points ; un service critique exposé de 2 à 3) ; pare-feu inactif plafonne le score à 3/10
- **Score de sécurité** 0–10 avec niveau de risque : FAIBLE / MOYEN / ÉLEVÉ / CRITIQUE ; findings répartis en *Action requise* / *Améliorations possibles* / *Configuration normale*
- **Profils d'audit** — `server` (défaut), `desktop`, `workstation`, `container` ; profil actif affiché dans la boîte de synthèse. **v0.8.1 BREAKING** : `workstation` n'est plus un alias de `desktop` et ship ses propres overrides business-tier (backup / auditd / mac_policy restent à WARN alors que desktop les relâche à INFO)
- **Cartographie CIS inline** — chaque finding affiche son code CIS `[CIS:X.Y.Z]` dans la boîte de synthèse ; référence complète en mode `--verbose` ; 199 entrées (108 CIS formels, 84 best-practice, 7 Docker)
- **5 en-têtes de groupes thématiques** — sortie organisée en : FIREWALL & RÉSEAU / EXPOSITION & SERVICES / CONTRÔLE D'ACCÈS / DURCISSEMENT SYSTÈME / DÉTECTION & SANTÉ
- **`--target N`** — objectif de score (1–10) ; affiché dans la boîte de synthèse ; retourne le code de sortie 4 si score < cible, **et depuis la v0.16.2 dès que quelque chose n'a pas pu être lu** — un score que rien n'a vérifié ne peut pas satisfaire un portail (intégration CI). La v0.16.0 disait « dès que le score est une borne supérieure » ; cela ne couvrait plus le cas où l'aveuglement retire un domaine de notation entier, l'exécution la moins fiable de toutes.

### Réseau & pare-feu

- **38 services réseau connus** détectés avec analyse d'exposition UFW et contexte de risque à deux axes (exposition + menace) pour les services critiques et élevés ; services CRITICAL/HIGH installés mais inactifs émettent ⚠ + bloc de contexte de risque
- **Panorama des services** — tableau compact des 38 services après l'audit : SERVICE / STATUT / PORT(S) / UFW ; services non installés affichés en grisé. Les états viennent de systemd ou — depuis la v0.18.0 — d'OpenRC sur les machines qui n'en ont pas (Alpine, Gentoo, Devuan) : les codes de retour de `rc-service status` sont lus et l'existence est établie par `/etc/init.d/<nom>`, si bien qu'une sonde qui n'a pas pu tourner n'est jamais lue comme un démon arrêté. Un service **activé mais arrêté** est signalé et compté comme son miroir, *en marche mais non activé*
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
- **Audit de sécurité SSH** — analyse complète de `sshd_config` (12 directives à règle de valeur, plus les listes d'accès AllowUsers/AllowGroups/DenyUsers/DenyGroups et les Ciphers/MACs/KEX faibles) ; audit des clés privées (type, taille, passphrase) ; inspection `authorized_keys` ; vérification côté client `~/.ssh/config` ; comptage `known_hosts` ; suggestions d'installation adaptées à la distro
- **Fichiers sensibles & sudoers** — audit des permissions de `/etc/passwd`, `/etc/shadow`, `/etc/gshadow`, `/etc/group`, `/etc/sudoers` ; permissions des clés hôtes SSH ; détection de `NOPASSWD:ALL` dans sudoers et sudoers.d
- **Audit SUID/SGID** — binaires SUID et SGID appartenant à root hors de l'ensemble attendu (liste blanche dans `config.conf`) → WARN −1 pt. Depuis la v0.18.0, chacun est aussi **attribué à son paquet** (`dpkg -S`, `rpm -qf`, `pacman -Qo`, `apk info --who-owns`) : un binaire SUID root qu'**aucun paquet ne fournit** est un constat à part entière → ALERT −2 pts — la forme que prend une élévation de privilèges laissée derrière soi. Une requête qui répond sur elle-même plutôt que sur le fichier (base verrouillée, gestionnaire absent) ne produit aucun constat, et ne devient donc jamais une accusation
- **Audit des mises à jour système** — paquets de sécurité en attente via `apt-get -s upgrade` (−2 pts fixe) ; absence de `unattended-upgrades` combinée à des mises à jour de sécurité en attente (−1 pt composé) ; mises à jour régulières → INFO uniquement
- **Audit umask système** — lit le umask depuis `/etc/login.defs`, PAM, `/etc/profile`, RC shells et processus courant ; umask permissif (0002/0000) → WARN −1 pt ; sources conflictuelles → WARN −1 pt
- **Secure Boot** — état UEFI via `mokutil --sb-state` / `efivars` / `bootctl` ; WARN −1 pt si désactivé sur desktop ; INFO sur server/VM ou BIOS/inconnu
- **Audit firmware & microcode** — `fwupdmgr` firmware device en attente ; paquet microcode CPU (Intel/AMD) ; WARN −1 pt si absent ou obsolète
- **Expiration certificats TLS/SSL** — analyse Let's Encrypt, `/etc/ssl/private`, directives nginx/apache2/postfix ; expiré → ALERT −2 pts ; <7 j → ALERT −2 pts ; <30 j → WARN −1 pt ; total plafonné à −4 pts ; liens symboliques cassés gérés
- **Sécurité timers systemd** — curl/wget pipé vers un shell dans ExecStart → WARN −2 pts ; scripts world-writable dans ExecStart → WARN −1 pt ; timers root créés par l'utilisateur sans `User=` → INFO
- **Durcissement des services (`systemd-analyze security`)** — remonte le score d'exposition systemd des services en cours (NoNewPrivileges, ProtectSystem, capability bounding, namespacing…) ; résumé INFO uniquement (compte par prédicat + services en cours les moins durcis + pointeur `systemd-analyze security <unit>`), **aucune déduction** — une exposition élevée par défaut est l'état normal d'un hôte Linux, pas une mauvaise configuration choisie (v0.13.0)
- **Posture de sécurité du conteneur** — quand BOB tourne *dans* un conteneur, lit l'isolation du conteneur depuis les interfaces noyau (jeu de capabilities → détection privilégié / CAP_SYS_ADMIN, mode seccomp, mapping user namespace, rootfs en écriture) ; la section entière est supprimée hors conteneur. INFO uniquement en v0.13.0 ; le fast-follow qu'elle annonçait a atterri en **v0.15.4**, validé contre quatre conteneurs podman réels : privileged −3, CAP_SYS_ADMIN −2, seccomp désactivé −1. Les défauts du runtime (racine inscriptible, root sans espace de noms utilisateur) restent INFO — un choix opérateur est pénalisé, un défaut éditeur ne l'est pas (v0.13.0, dents v0.15.4)
- **Unités socket systemd** — signale les unités `.socket` encore actives alors que leur service backing a disparu (masqué / introuvable) ou en état failed — une socket en écoute sans consommateur fonctionnel, typiquement le résidu d'un paquet supprimé/renommé ; marque celles liées à une adresse non-loopback. Les internes systemd à trigger vide ne sont jamais flaguées. **v0.15.4** : une orpheline liée à une adresse non-loopback déduit −1 — le port répond puis fait échouer la connexion ; la même panne sur loopback reste INFO (v0.13.1, dents v0.15.4)
- **Contexte cloud (côté hôte)** — uniquement sur une instance cloud (détection conservatrice : un fournisseur identifié via SMBIOS/DMI, ou cloud-init corroboré par une route de métadonnées on-link — un simple cloud-init installé sur une VM Proxmox/VMware/homelab n'est *pas* considéré comme du cloud) : remonte l'exposition cloud visible depuis l'hôte — service de métadonnées joignable on-link (rappel IMDSv2), user-data persistée lisible par tous — strictement côté hôte, aucune API/identifiant cloud. **v0.15.4** : le user-data lisible par tous déduit −2 (cloud-init l'écrit en 0600, donc tout autre mode est un choix). L'accessibilité de l'IMDS reste INFO : savoir si IMDSv2 est imposé est une propriété des metadata options de l'instance et ne se lit pas depuis l'hôte (v0.13.1, dents v0.15.4)

### Détection & surveillance

- **Logs UFW** — parse `/var/log/ufw.log` sur une période configurable (`--log-days=N`, défaut 7 jours) ; total des tentatives bloquées, top IPs sources avec géolocalisation, top ports ciblés, détection bruteforce (>10 tentatives/60 s), tentatives sur ports de services installés
- **Analyse auth.log SSH** — parse `/var/log/auth.log` ; détection brute-force (≥50 tentatives échouées sur toute la période analysée, toutes sources confondues → WARN, sans déduction) ; dernières connexions réussies ; top sources d'échec
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
- **Moteur de corrélation de signaux** — 6 règles de risque composé (root+sans-fail2ban, auth-password+brute-force, root+password, NOPASSWD+SUID, maj-sécurité-en-attente+sans-fail2ban, logging-off+sans-fail2ban+sans-auditd) ; évalué post-audit sur les findings ALERT+WARN actifs
- **Suivi des findings récurrents** — compteur d'apparitions consécutives par clé ALERT/WARN ; stocké dans `~/.config/bob/recurrence.json`
- **Détection d'applications de bureau** — applis GUI connues (Steam, Discord, Zoom, Signal, VLC, Spotify, Slack, Telegram, Chrome, Firefox…) en cours d'exécution ; findings INFO, sans déduction

### Sortie & UX

- **Interface bilingue** — détection automatique depuis `$LC_ALL`/`$LC_MESSAGES`/`$LANG` (POSIX) ; retombe sur l'anglais quand la locale est `C`/`POSIX` ou non supportée. Forcer avec `--french` / `--english` (ou `--lang=fr` / `--lang=en`)
- **Gestion de la couleur** — auto-détectée depuis la v0.14.0 : l'ANSI n'est émis que si stdout est un terminal, donc rediriger vers un fichier ou un pipe est propre sans aucune option. `--no-color` (ou `NO_COLOR=1`) la force à off ; `FORCE_COLOR=1` la force à on pour `less -R` ou un log volontairement coloré
- **Mode fix** — section interactive après le résumé ; chaque correction automatisable demande une confirmation `[y/N]` ; `--fix` seul affiche un aperçu sans exécuter ; `--fix --apply --yes` confirme tout avec journal d'audit **Seule une commande que BOB peut exécuter sans surveillance est comptée comme automatique** : `cmd_type="fix"` (un diagnostic comme `smartctl -a` n'est pas une remédiation), aucun opérateur shell, aucun éditeur interactif. Tout le reste apparaît sous son propre titre, commande affichée mais non exécutée — le compteur au-dessus de l'invite est une promesse tenable, depuis la v0.17.1. Les commandes d'installation portent `-y`, car un correctif qui s'arrête pour poser une question ne peut pas être appliqué par un mode dont tout l'objet est de ne pas en poser.. Depuis la v0.18.0, les durcissements sysctl sont appliqués **par le code de BOB, pas par un shell** : la valeur est posée, persistée avec exactement une ligne par clé, puis **relue** avant que BOB n'affirme quoi que ce soit — la commande affichée reste la même pour qui veut la coller. Deux applications sans surveillance sont refusées d'office parce qu'elles peuvent vous faire perdre une machine distante — une politique de pare-feu de refus par défaut (`iptables -P INPUT DROP` et ses variantes `ip6tables`, `-nft`, `-legacy` et `nft … policy drop`) — et un correctif qui ouvre un accès (`ufw allow`) passe toujours avant celui qui en retire (`ufw enable`)
- **`--explain KEY`** — explication structurée par constat (POURQUOI / COMMENT CORRIGER / référence CIS) ; 194 clés sur 50 préfixes ; 109 d'entre elles rendent une section par profil — 71 avec une prose écrite pour lui, les autres avec une note dérivée du fichier de profil — et 85 s'appliquent identiquement à tous les profils ; TUI interactif ; sans droit root ; la vue par clé ajoute un bloc **Aussi référencé dans** listant le numéro du même contrôle dans chaque autre benchmark qui le couvre ; `--explain list` et le wizard groupent toutes les clés en arborescence de dossiers à trois niveaux — distribution CIS (CIS Ubuntu, CIS Debian, CIS Docker, CIS Red Hat, Bonne pratique) → version de benchmark (Ubuntu 22.04/24.04, Debian 12/13) → section de type
- **Scores par domaine** — sous-scores 0–10 (SSH / Samba / Fichiers & Accès / Mises à jour / Durcissement / Santé Disque / Pare-feu & Services) ; score global = moyenne des scores de domaine actifs (un domaine devient actif dès qu'un check émet `OK`, `WARN` ou `ALERT` — les domaines `INFO`-only restent cachés ; `OK` a été ajouté au set actif en v0.4.6 pour corriger une inversion de score après remédiation) ; plafonds par outil pour éviter la double pénalité (rootkit, ClamAV, intégrité fichiers plafonnés à 1 pt de déduction chacun) ; barre █/░ après l'audit ; inclus dans JSON et webhook
- **Webhooks** — `--webhook URL` envoie le résultat en JSON ; formats générique et Slack (auto-détecté) ; `--webhook-format=auto|generic|slack`
- **Export HTML `--html`** — fichier HTML autosuffisant (sans JS, sans ressources externes) ; cercle de score coloré ; badges ALERT/WARN/INFO/OK ; tableau déductions ; protection XSS
- **`--format=FORMAT`** — flag unifié : `json | json-full | csv | markdown | html` ; anciens flags conservés comme aliases. Depuis la v0.18.0, la dernière colonne du CSV est `key`, l'identifiant stable du constat — le même que portent `--explain`, `--ignore` et le JSON ; les quinze colonnes précédentes gardent leur position
- **`--check LIST` / `--skip LIST`** — n'exécuter que les checks nommés ou les exclure ; mutuellement exclusifs ; `--check=list` affiche les 48 noms de sections — les 38 filtrables, plus les 10 toujours actives qu'il liste aussi
- **`--output-dir PATH`** — surcharger le répertoire de sauvegarde pour l'exécution courante ; sans persistance
- **Rapport comparatif** — baseline enregistrée après chaque audit ; au prochain lancement : delta de score, variations alertes/avertissements, ports apparus/fermés, services démarrés/arrêtés ; clés ALERT+WARN nouvelles et résolues suivies séparément. Un fichier qui n'est pas une baseline BOB (sans `timestamp` ni `score`) est refusé nommément au lieu d'être comparé comme une baseline à zéro
- **Historique des scores** — `--history` affiche les N derniers scores en sparkline (▁▂▃▄▅▆▇█) avec dates ; rotation automatique à 1000 entrées. Une ligne dont BOB ne sait lire ni le score ni l'horodatage est ignorée, jamais réparée en un chiffre qu'il n'a pas mesuré
- **Liste d'exceptions** — `--ignore KEY` ajoute une clé dans `ignore.yml` ; `--show-ignored` lance l'audit et affiche en gris les constats supprimés à côté de la sortie normale (ce n'est pas une commande de listing) ; les findings correspondants sont masqués sans être scorés
- **Mode `--diff`** — lance l'audit silencieusement et affiche uniquement le delta (score, alertes, avertissements, INFO)
- **`--breakdown` / `-B`** — lance l'audit silencieusement et affiche le chemin complet de calcul du score : toutes les déductions (clé · domaine · points · contexte), plafonds par outil, plafond moteur, score brut, scores par domaine avec barres de progression, surcharge de moyenne, score final coloré
- **API Plugin** — déposer un fichier Python dans `~/.config/bob/checks.d/` pour ajouter une vérification personnalisée ; fail-safe (les exceptions n'interrompent jamais l'audit) ; séquences ANSI nettoyées

### Automatisation

- **Rapport détaillé** — fichier log horodaté avec en-tête ASCII art, informations système, findings et recommandations ; créé avec `-d` ; nom : `bob_YYYYMMDD_HHMMSS.log`. Chaque constat porte son explication, sa commande (`→` correctif, `?` vérification) et sa clé — sans condition, et aussi sous `-q`, car une archive ne se relance pas avec `-v`
- **`--manage-logs`** — interface interactive pour lister, prévisualiser et supprimer les rapports ; prévisualisation scrollable avec bascule résumé/complet
- **`--install-cron`** — wizard de planification : nom du cron, type de planning (quotidien / jours spécifiques / expression cron personnalisée), heure et email optionnel, puis fixation du profil, de la langue et des sondes sortantes de l'audit (v0.16.1 — un cron s'exécute en root : sans cela il lirait le profil enregistré de root et le `$LANG` nu de cron) ; détection automatique du MTA (Postfix, Exim, msmtp, ssmtp) — avertit si aucun `sendmail` trouvé ; aperçu en langage naturel ; ligne de commande résultante affichée avant écriture ; TUI curses avec repli texte ; crons nommés dans `/etc/cron.d/bob-{nom}`
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
| Vaultwarden (gestionnaire de mots de passe) | 8000/tcp, 3012/tcp | Élevé | Détient tous les identifiants de l'hôte ; l'exposer transforme une brèche en toutes  |
| Authelia (proxy SSO/auth)        | 9091/tcp             | Élevé    | Protège tous les services derrière lui ; un contournement ici les contourne tous    |
| Caddy Web Server                 | 80/tcp, 443/tcp      | Moyen    | Public par conception ; TLS automatique, mais toute erreur de vhost est exposée     |
| AdGuard Home (puits DNS)         | 53/udp, 53/tcp, 3000/tcp | Moyen | Risque de résolveur DNS ouvert si exposé ; l'UI d'admin sur 3000 est une exposition distincte |
| Ollama (LLM local)               | 11434/tcp            | Moyen    | API sans authentification par défaut ; l'exposer donne accès aux modèles et prompts |
| Tailscale VPN                    | 41641/udp            | Faible   | Maillage WireGuard ; le port est le transport chiffré, pas une surface d'administration |

> **ℹ Note sur la couverture des services :** La détection et la classification des services suivants ont été validées par des tests réels : SSH, Samba, Avahi, CUPS, Redis, WireGuard, Docker, Mosquitto, Syncthing, Nginx. Les autres services sont implémentés mais pas encore validés par un protocole de test formel. Si vous utilisez l'un de ces services et observez un comportement incorrect, merci d'ouvrir une issue sur GitHub.

---

## Prérequis

- Linux — le badge de plateformes couvre neuf noms, sur trois natures de preuve différentes :
  - **utilisé au quotidien** : Linux Mint 22.3, Debian 13.4.0
  - **validé en CI** (conteneurs, à chaque push) : Debian 12/13, Ubuntu 22.04/24.04/25.04, Kali Rolling, Fedora 41
  - **validé sur machines virtuelles réelles** (tests terrain v0.17.1 et v0.18.0) : Fedora 43, Kali 2026.2, openSUSE Leap 15.6, Arch Linux, Alpine 3.22 — Alpine étant la seule machine sans systemd, celle contre laquelle le support OpenRC a été écrit
  - **Raspberry Pi** : audité sur du vrai matériel pour la première fois en v0.18.1 — un Pi Zero W (ARMv6, 426 Mo) sous Raspbian 13 trixie. Un audit complet y prend 71 à 108 s. La passe a montré la détection de force brute SSH aveugle sous OpenSSH ≥ 9.8 et le contrôle de la partition de démarrage cherchant le mauvais fichier de provisionnement ; les deux sont corrigés et rejoués sur la carte. C'est une carte et une version d'OS, pas une matrice
- Python 3.10+
- `ss` recommandé (paquet `iproute2`) — disponible par défaut sur les systèmes modernes
- `python3-geoip2` + base GeoLite2 recommandés pour la géolocalisation IP (optionnel) : `sudo apt install python3-geoip2 geoip-database`
- `docker` CLI pour l'analyse Docker (optionnel)

---

## Installation

### Prérequis

- Linux — le badge de plateformes couvre neuf noms, sur trois natures de preuve différentes :
  - **utilisé au quotidien** : Linux Mint 22.3, Debian 13.4.0
  - **validé en CI** (conteneurs, à chaque push) : Debian 12/13, Ubuntu 22.04/24.04/25.04, Kali Rolling, Fedora 41
  - **validé sur machines virtuelles réelles** (tests terrain v0.17.1 et v0.18.0) : Fedora 43, Kali 2026.2, openSUSE Leap 15.6, Arch Linux, Alpine 3.22 — Alpine étant la seule machine sans systemd, celle contre laquelle le support OpenRC a été écrit
  - **Raspberry Pi** : audité sur du vrai matériel pour la première fois en v0.18.1 — un Pi Zero W (ARMv6, 426 Mo) sous Raspbian 13 trixie. Un audit complet y prend 71 à 108 s. La passe a montré la détection de force brute SSH aveugle sous OpenSSH ≥ 9.8 et le contrôle de la partition de démarrage cherchant le mauvais fichier de provisionnement ; les deux sont corrigés et rejoués sur la carte. C'est une carte et une version d'OS, pas une matrice
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

# Mode fix — prévisualise les corrections disponibles (à blanc, rien n'est exécuté)
sudo bob -f

# Mode fix — applique toutes les corrections sans confirmation (--apply est requis)
sudo bob -f --apply -y

# Sortie sans couleur (utile pour les pipes et la redirection)
sudo bob -n > audit.txt

# Analyser les logs sur 14 jours au lieu de 7
sudo bob --log-days=14

# Supprimer la configuration enregistrée (avec confirmation)
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

## Configuration enregistrée

`~/.config/bob/config.conf` (mode `0600`) contient le profil d'audit, l'URL et le format du webhook, la liste blanche SUID et les répertoires de journaux choisis via `--manage-logs`. Rien d'autre n'est persisté : **les ports des services ne sont pas enregistrés et ne l'ont jamais été** — BOB lit à chaque audit les fichiers de configuration des services eux-mêmes (`sshd_config`, `nginx.conf`, `smb.conf`, …) et retombe sur le port usuel quand aucune directive n'est trouvée. Des versions antérieures de cette page décrivaient une invite proposant de mémoriser un port non standard ; cette invite n'existe pas dans le code.

Pour supprimer la configuration enregistrée et repartir des valeurs par défaut (avec confirmation) :

```bash
sudo bob -r
```

---

## Plugins de check — `~/.config/bob/checks.d/*.py`

BOB supporte des checks d'audit personnalisés écrits en Python. Posez un fichier `*.py` dans `~/.config/bob/checks.d/` et BOB le picke au run suivant. Chaque plugin est exécuté dans un **sous-processus sandboxé** (introduit en v0.7.0 T3) — RLIMIT_AS 256 MiB, RLIMIT_CPU 10 s wall clock, allowlist d'import restreinte, écritures filesystem refusées, lectures bloquées sur chemins sensibles (`/etc/shadow`, `~/.ssh/id_*`, `/dev/mem`, …). Un plugin défaillant **ne peut pas** interrompre l'audit, et toute sortie est ANSI-sanitisée.

> **Note threat model :** le sandboxing Python in-process est de la défense en profondeur, pas une frontière de sécurité dure (consensus PEP 416). Utilisez le profil AppArmor shippé pour une vraie isolation. Voir SECURITY_FR.md → section "Plugin checks".

### Contrat

Chaque fichier plugin doit exposer une fonction :

```python
def run_check(t=None) -> CheckResult:
    ...
```

`t` est le callable i18n bound (rarement nécessaire dans un plugin — écrivez vos messages directement en français ou anglais). La valeur de retour est un `bob.scoring.CheckResult`. Optionnellement, définissez un `CHECK_NAME` au niveau module pour surcharger le titre de section dans le rapport.

### Exemple minimal fonctionnel

Sauvegardez ceci en `~/.config/bob/checks.d/motd_check.py` :

```python
"""Vérifie que /etc/motd contient une bannière."""
from pathlib import Path
from bob.scoring import CheckResult

CHECK_NAME = "VÉRIFICATION BANNIÈRE MOTD"

def run_check(t=None) -> CheckResult:
    result = CheckResult()
    motd = Path("/etc/motd")
    if motd.exists() and motd.read_text().strip():
        result.ok(message="Bannière MOTD personnalisée présente")
    else:
        result.info(
            message="Aucune bannière MOTD configurée",
            key="custom.motd_empty",
        )
    return result
```

### Méthodes de résultat

`CheckResult` expose les mêmes méthodes d'émission que les checks built-in :

- `result.ok(message=...)` — coche verte, pas d'impact score
- `result.info(message=..., key=...)` — notice neutre, pas de déduction
- `result.warn(message=..., key=..., points=..., nature=...)` — avertissement jaune
- `result.alert(message=..., key=..., points=..., nature=...)` — alerte rouge
- `result.warn_with_deduction(...)` / `result.alert_with_deduction(...)` — helpers combinés

Utilisez `key=` pour que votre finding puisse être silencé avec `bob --ignore custom.ma_cle` si besoin. Choisissez des chaînes `key` sous un préfixe `custom.*` pour éviter les collisions avec les clés built-in (le test invariant `_KNOWN_PREFIXES` rejette les préfixes inconnus pour les EXPLAIN_KEYS built-in mais pas pour la sortie plugin).

### Ce que les plugins NE peuvent PAS faire

Dans le sandbox enfant :

- Pas de subprocess (`subprocess.run`, `os.popen`, `os.exec*` — tous strippés ou refusés).
- Pas d'écriture filesystem (`open(... 'w')`, `os.write`, `Path.write_*`, les méthodes write de `pathlib.Path` sont monkey-patchées).
- Pas de lecture sur `/etc/shadow`, `~/.ssh/id_*`, `/dev/mem`, `/proc/kcore`, et chemins sensibles similaires.
- Pas d'`__import__` de modules arbitraires — uniquement une allowlist (bob.scoring, pathlib, json, etc.).
- Pas d'I/O réseau.

Si un plugin tente l'une des opérations ci-dessus, il raise dans le sandbox enfant, le parent enregistre un finding WARN sous l'une des douze clés `plugin.sandbox.*` (`error`, `rejected`, `crashed`, `timeout`, `syntax_error`, `unreadable`, `bad_payload`, `bad_return`, `no_result`, `missing_run_check`, `runner_error`, `serialize_failed`) — un `--ignore plugin.sandbox.error` en masque une, pas les échecs de plugin en général, et l'audit continue intact.

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
║  BOB v0.18.1  │  Auditeur de durcissement Linux                              ║
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
| `-f`, `--fix`           | Prévisualiser les corrections disponibles (à blanc — rien n'est exécuté) |
| `-y`, `--yes`           | Confirmer automatiquement toutes les corrections avec journal d'audit (nécessite `--fix --apply`) |
| `-r`, `--reconfigure`   | Supprimer la configuration enregistrée puis sortir (avec confirm.) |
| `-n`, `--no-color`      | Forcer la couleur à off (elle est auto-détectée depuis le TTY)     |
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
| `-p`, `--profile=NOM`   | Profil d'audit : `server` (défaut), `desktop`, `workstation`, `container` |
| `--check=LISTE`         | N'exécuter que ces checks (séparés par des virgules) ; `--check=list` affiche tous les noms |
| `--skip=LISTE`          | Ignorer ces checks (séparés par des virgules ; exclusif avec `--check`) |
| `--target=N`            | Cible de score (1–10) : écart, succès ou plafond ; sortie 4 si non atteinte — ou si le score n'a pas pu être vérifié |
| `--min-level=NIVEAU`    | N'afficher que les constats au niveau `warn` ou `alert` et au-dessus (le contexte d'exécution est inchangé) |
| `--apply`               | Exécuter les corrections interactivement (nécessite `--fix`)       |
| `--output=FORMAT`       | Alias de `--format` (à ne pas confondre avec `--output-dir`)       |
| `--output-dir=CHEMIN`   | Enregistrer le rapport détaillé dans CHEMIN (prime sur la config enregistrée) |
| `--html`                | Alias long de `--format=html`                                      |
| `--watch[=N]`           | Relancer l'audit toutes les N secondes (défaut 60) — Ctrl+C pour quitter |
| `--history`             | Afficher la sparkline d'historique de score et la table récente, puis sortir |
| `--ignore=CLÉ`          | Ajouter une clé de constat à la liste d'exclusion et sortir        |
| `--unignore=CLÉ`        | Retirer une clé de constat de la liste d'exclusion et sortir       |
| `--show-ignored`        | Afficher en gris les constats supprimés à côté de la sortie normale |
| `--reset-baseline`      | Supprimer la baseline d'audit enregistrée et sortir                |
| `--test-email`          | Envoyer un vrai message de test par le transport mail du cron et sortir |
| `--test-webhook`        | Envoyer une charge de test au webhook configuré et sortir (sans audit) |
| `-C`, `--manage-cron`   | Interface interactive pour lister, éditer ou supprimer les tâches cron installées |
| `--lang=CODE`           | Langue de l'interface : `en`, `fr` (défaut : détectée depuis `$LANG`) |
| `--no-colour`           | Alias orthographique de `--no-color`                               |
| `--french`              | Passer l'interface en français                                     |
| `--english`             | Passer l'interface en anglais (symétrie avec `--french`, v0.12.1)  |
| `-V`, `--version`       | Afficher la version et quitter (sans sudo)                         |
| `-h`, `--help`          | Afficher l'aide et quitter (sans sudo)                             |

---

## Fichiers

| Fichier                                  | Description                                                              |
|------------------------------------------|--------------------------------------------------------------------------|
| `~/.local/bin/bob`                 | Point d'entrée pipx                                                      |
| `/usr/local/bin/bob`               | Lien symbolique pour l'accès sudo (créé par `--install-completion`)      |
| `/etc/bash_completion.d/bob`       | Autocomplétion bash (créée par `--install-completion`)                   |
| `/usr/local/bin/bob-<nom>`         | Script wrapper par tâche installée, `<nom>` étant le nom de tâche choisi à l'installation (créé par `--install-cron`). `bob-nightly` est le nom fixe d'avant la v0.12, toujours reconnu à la lecture des tâches existantes. |
| `/etc/cron.d/bob-{nom}`            | Entrée cron nommée (créée par `--install-cron`)                          |
| `~/.config/bob/config.conf`        | Configuration utilisateur (profil, webhook, répertoire logs ; 600)       |
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
  "detection": {
    "binary":       ["/usr/local/bin/myapp"],
    "snap":         ["myapp-snap"],
    "config_files": ["/etc/myapp/config.yml"]
  }
}
```

**Champs obligatoires :** `id`, `label`, `packages`, `services`, `ports`, `risk`. **Optionnel :** `detection`. `risk` ∈ `{"low", "medium", "high", "critical"}`. `config_key` vaut `"fixed"`, `"ask"`, `"auto"`, ou un identifier Python. **Plage de port 1–65535** (stricte).

**Contraintes métier appliquées par le schéma :**

- Un service doit déclarer au moins un port **ou** une entrée `detection.config_files` d'où les lire. N'en déclarer aucun est refusé : ses ports ne pourraient jamais être déterminés.
- `config_key` est retiré en v0.15.4. Il reste accepté pour que les `~/.config/bob/services.d/*.json` existants continuent de valider, mais il est ignoré.
- Un service doit être détectable : au moins un parmi `packages`, `services`, ou `detection.{binary|snap}` doit être non-vide.
- Un bloc `detection: {}` vide est rejeté (n'apporte aucun signal).

**Forme du fichier plugin.** Un fichier plugin utilisateur sous `~/.config/bob/services.d/*.json` peut utiliser l'une des deux formes équivalentes :

1. **Tableau brut** (legacy / défaut actuel) — un tableau JSON nu d'objets service.
2. **Objet wrappé** (forward-compat) — `{"schema_version": 1, "services": [ ... ]}`. Le wrapper existe pour que les futures migrations de schéma puissent être gatées explicitement via `schema_version`. Seul `schema_version: 1` est accepté aujourd'hui ; les champs réservés comme `metadata`, `disabled` sont marqués pour les versions futures.

Voir `bob/data/schemas/plugin-file.schema.json` pour le méta-schéma du wrapper. Valider en externe avec n'importe quel outil JSON Schema 2020-12 (e.g. `check-jsonschema`, `ajv`).

**Scope du schéma.** Le schéma valide la structure et la forme syntaxique. Il **n'applique pas** : l'unicité cross-service de `id` (check runtime) et l'obligation qu'un service déclare soit un port, soit un fichier de configuration d'où le lire (check runtime). Un document conforme au schéma peut quand même être rejeté au chargement si ces invariants runtime sont violés — la source de vérité canonique reste `bob.registry.Service.from_dict()`.

---

## Variables d'environnement

Toutes sont opt-in ; aucune n'est requise pour un fonctionnement normal.

| Variable | Effet |
|---|---|
| `NO_COLOR` | Toute valeur non vide force la couleur à off, comme `--no-color`. Une valeur vide est ignorée ([no-color.org](https://no-color.org)). |
| `FORCE_COLOR` | Toute valeur non vide force la couleur à **on** même si stdout n'est pas un terminal — pour `bob \| less -R`, ou pour capturer volontairement un log coloré. Ajoutée en v0.14.0 avec l'auto-détection TTY. |
| `BOB_DEBUG` | Diagnostic : affiche la traceback Python complète sur une sortie `EXIT_ERROR`, et installe un vrai handler de logging pour rendre visibles les enregistrements internes `logger.debug` / `logger.warning` (notamment la trace d'échec par subprocess de `_run()`). |
| `BOB_SHARE` | Force le chemin du dossier de données du package (`bob/data/`). Pour les packageurs distro qui livrent les données hors de l'arbre Python. |
| `BOB_WEBHOOK_ALLOW_INSECURE` | Mettre à `1` pour autoriser une URL de webhook en `http://` simple. Les webhooks sont en HTTPS uniquement depuis la v0.7.1, car la charge utile transporte les constats de l'hôte ; sans cette variable, une URL `http://` est refusée avec le motif. Également documentée dans la frontière de confiance de SECURITY_FR.md |

Précédence de la couleur, première correspondance gagnante : `--no-color` → `NO_COLOR` → `FORCE_COLOR` → `stdout.isatty()`.

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
| `4`  | `EXIT_TARGET_MISSED` | `--target N` spécifié et score < N, **ou quelque chose n'a pas pu être lu** (v0.16.2, élargi depuis « borne supérieure ») : un check n'a pas pu lire son entrée, donc « au moins N » n'a jamais été établi. Un portail échoue fermé. |
| `130`| *(convention signal)* | Interrompu par Ctrl-C. Depuis la v0.14.1, `main()` attrape `KeyboardInterrupt` et affiche une ligne localisée au lieu d'un traceback Python. Ce n'est pas une constante de `bob.__main__` — c'est le `128 + SIGINT` du shell. |

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

### Versions du schéma

Le schéma **v3** est la seule version émise par `bob.json_output.build_json_data()` :

| Version | Statut | Sélection |
|---|---|---|
| **v3** | **Défaut et unique schéma depuis v0.12.0** | `--json` / `--json-full` |
| v2 | Schéma v0.7.0 — **retiré en v0.12.0** (renommage des compteurs F9) | (plus disponible) |
| v1 | Schéma legacy v0.6.x — **retiré en v0.9.0** | (plus disponible) |

v1 (et son flag opt-in `--json-v1`) a été retiré en v0.9.0 ; **v2 a été retiré en v0.12.0** quand F9 a renommé les compteurs entiers `alerts`→`alert_count` et `warnings`→`warning_count` par symétrie avec `info_count` — un renommage breaking, donc le majeur passe de v2 à v3 plutôt que de muter v2 en place. Les consommateurs figés sur v2 doivent se re-figer sur v3 et renommer ces deux clés :

```bash
sudo bob --json | jq '.schema_version'   # → "3"
```

### v3 — Clés top-level (toujours présentes)

| Clé | Type | Description |
|---|---|---|
| `schema_version` | string | `"3"` |
| `version` | string | Version de BOB qui produit la sortie |
| `host` | string | Nom d'hôte (`uname -n`) |
| `timestamp_utc` | string | Timestamp UTC ISO 8601 (renommé depuis `timestamp` en v1) |
| `score` | int (0–10) | Score de sécurité global |
| `score_max` | int | Toujours `10` |
| `risk` | string | Niveau de risque **effectif** (inclut l'escalation posture) : `"low"`, `"medium"`, `"high"`, `"critical"` |
| `network_context` | object | `{ "context": "local" \| "public" \| "ddns" }` en mode court (`"ddns"` est une promotion de `"local"` appliquée quand le DDNS est actif avec un port ouvert non restreint, pour que l'exposition soit scorée au poids public) ; étendu avec `interfaces`, `connections_count`, `top_remote_ips` en `--json-full` |
| `public_ip` | string | IP publique (vide derrière NAT) |
| `alert_count` | int | Nombre de findings ALERT (renommé depuis `alerts` en v0.12.0) |
| `warning_count` | int | Nombre de findings WARN (renommé depuis `warnings` en v0.12.0) |
| `info_count` | int | Nombre de findings INFO (nouveau en v2) |
| `profile` | string | Le profil d'audit qui a produit ce résultat (`server` / `desktop` / `workstation` / `container`). Nouveau en v0.14.1, additif dans v3. Depuis la v0.14.0 le profil change les sévérités des findings, `warning_count` et donc le code de sortie : deux payloads du même hôte peuvent légitimement diverger, et c'est ce champ qui l'explique. |
| `duration_seconds` | float \| null | Durée de l'audit en secondes, arrondie à la milliseconde. Mesurée depuis le démarrage des checks — pas depuis l'entrée du processus, donc hors analyse des arguments et vérification root — avec une horloge monotone, si bien qu'un ajustement d'horloge en cours d'exécution ne peut pas la rendre négative. `null` quand l'exécution ne s'est pas chronométrée. Nouveau en v0.17.1, additif dans v3. |
| `degraded_sections` | array | Noms des sections dont le check a levé une exception et qui ont été dégradées sur place au lieu d'interrompre l'audit (nouveau en v0.14.1, additif dans v3). Vide sur une exécution saine. Chacune apparaît aussi comme un finding INFO `<section>.unavailable`. Permet de distinguer « score 9, toutes sections évaluées » de « score 9, deux sections jamais exécutées ». |
| `score_is_upper_bound` | bool | **Nouveau en v0.16.0, restreint en v0.16.2.** Vrai quand le score ne peut être que *trop haut* : un check n'a pas pu lire son entrée, donc les déductions qu'il n'a pas faites sont inconnues, pas nulles. Masquer `/etc/ssh/sshd_config` retire quatre déductions et fait passer le score de 7 à **8** — vers le haut, sur un hôte dont BOB voit moins. Depuis la v0.16.2, ce champ est **faux** quand l'aveuglement a retiré un domaine entier de la moyenne (`unscored_domains` non vide) : le dénominateur a changé, donc le score peut aussi descendre — masquer `/etc/passwd` le fait passer de 7 à 6, et appeler 6 un plafond affirmerait une borne en dessous de la vraie valeur. **La porte se lit sur `score_is_uncertain`, pas sur ce champ** : celui-là est vrai dès que quoi que ce soit n'a pas pu être lu, dans un sens comme dans l'autre. `score` reste un entier pour ne casser aucun consommateur. |
| `target` | int \| null | La valeur `--target N` de cette exécution, ou `null` si `--target` n'a pas été utilisé. |
| `target_met` | bool \| null | Si la cible est atteinte. `null` sans `--target`. Faux aussi quand le score n'a pas pu être vérifié — la porte lit `score_is_uncertain`, pas le score seul : une exécution non vérifiable échoue fermée. |
| `score_low` | int | Borne basse de l'intervalle où se trouve le vrai score, compte tenu de ce qui n'a pas pu être lu. Égale `score` si rien n'était aveugle. |
| `score_high` | int | Borne haute de cet intervalle. `score_low == score_high == score` sur une exécution entièrement lisible : le consommateur peut utiliser la paire sans condition. |
| `unscored_domains` | array | Domaines retirés de la moyenne du score parce que leur entrée était illisible. Non vide signifie que le dénominateur a changé : le score a bougé dans une direction imprévisible au lieu d'être seulement un plafond — c'est ce qui rend `score_is_upper_bound` faux alors que `score_is_uncertain` reste vrai. |
| `unverified` | array | **Nouveau en v0.16.0.** Les clés de constat signifiant qu'une section n'a pas pu être entièrement lue (`ssh.config_unreadable`, `suid_audit.ok_partial`, …). Vide sur un audit pleinement privilégié. Alerter sur `score_is_upper_bound` plutôt que compter cette liste : une seule section illisible suffit à faire du score un plafond. |
| `deductions` | array | Déductions de score (filtrées : `points > 0`) |
| `domain_scores` | object | Sous-scores par domaine |
| `posture_escalation` | object | Contexte de l'ajustement du niveau de risque par la posture (nouveau en v2) |

### v3 — Structure `posture_escalation` (nouvelle)

```json
{
  "applied":     false,
  "reason_key":  null,
  "score_level": "low"
}
```

| Champ | Type | Description |
|---|---|---|
| `applied` | bool | `true` quand le `risk` affiché a été remonté par un trigger posture |
| `reason_key` | string \| null | Clé i18n quand appliqué, ex. `"scoring.posture.firewall_inactive"` |
| `score_level` | string | Le niveau de risque calculé à partir du seul score, avant escalation posture |

Triggers (1er match wins) :

1. `firewall_inactive` → plancher `high`
2. `iptables_input_accept` → plancher `high`
3. `firewall_domain_score ≤ 3` → plancher `medium`

La Phase 1 (commit `e3d998f`) a introduit le concept posture en interne ; v2 le surface dans le JSON pour que les consommateurs distinguent « risque faible parce que clean » de « risque faible dominé par de bons domaines non-pare-feu ».

### v3 — Structure `deductions[]`

```json
{
  "reason": "Journalisation UFW désactivée",
  "points": 2,
  "key":    "firewall.logging_off",
  "template_vars": {}
}
```

Le champ `key` est une **clé i18n stable en notation pointée** (`<prefix>.<finding_id>`) — c'est sur ce champ qu'il faut matcher (et non sur `reason` localisée) pour une logique cliente stable entre locales. Voir l'audit EXPLAIN_KEYS ci-dessous pour la convention.

### v3 — Structure `domain_scores`

```json
{
  "ssh":        { "score": 10, "label": "SSH",                "deductions": 0, "active": true,  "reason": null },
  "samba":      { "score": 10, "label": "Samba Security",     "deductions": 0, "active": false, "reason": "not_installed" },
  "file_perms": { "score": 10, "label": "Files & Access",     "deductions": 0, "active": true,  "reason": null },
  "updates":    { "score": 10, "label": "Updates",            "deductions": 0, "active": false, "reason": "info_only" },
  "hardening":  { "score": 9,  "label": "Hardening",          "deductions": 1, "active": true,  "reason": null },
  "disk":       { "score": 10, "label": "Disk Health",        "deductions": 0, "active": false, "reason": "profile_skipped" },
  "firewall":   { "score": 10, "label": "Firewall & Services","deductions": 0, "active": true,  "reason": null }
}
```

Les clés de domaines sont stables : `ssh`, `samba`, `file_perms`, `updates`, `hardening`, `disk`, `firewall` (7 au total — définies dans `bob.domain_scores.DOMAINS`). Chaque entrée a `score` (int 0–10), `label` (nom d'affichage anglais), `deductions` (int — total des points déduits dans ce domaine, nouveau en v2), et **`active` / `reason` (nouveau en v0.12.1)**.

`active` (bool) vaut `true` quand le domaine a produit un finding actionnable (OK/WARN/ALERT) — **seuls les domaines actifs sont moyennés dans le `score` global**. Quand `active` vaut `false`, `reason` (string) explique pourquoi le domaine est affiché mais non scoré :

| `reason` | Signification |
|---|---|
| `info_only` | Les checks ont tourné et rapporté, mais seulement de l'informatif — rien à corriger. |
| `profile_skipped` | Le profil d'audit actif saute toutes les sections de ce domaine (ex. `disk` en profil `container`). |
| `filtered` | Exclu par un filtre `--check` / `--skip` sur ce run. |
| `not_installed` | Les checks ont tourné et trouvé le composant absent. |

Pour un domaine actif, `reason` vaut `null`. Cela permet à un consommateur de **reproduire le headline** : `score = round(moyenne(score des domaines actifs))`, plafonné à 9 dès qu'il y a une déduction (règle F1 "10 = audit sans défaut" — voir v0.12.0).

### v3 — Clés additionnelles en mode complet (`--json-full`)

| Clé | Type | Description |
|---|---|---|
| `findings` | array | Tous les findings avec `{ key, level, message, detail, nature, cmd, note, template_vars, qualified_by }`. `detail` est présent depuis la v0.8.1 et manquait à cette liste. **`qualified_by`** (nouveau en v0.15.5, additif) porte les clés des findings du même audit qui qualifient celui-ci — par exemple `ssh.config_newer_than_service`, qui indique que les constats SSH décrivent le fichier de configuration et non le service en cours. Un consommateur qui ne lit que `key` ne peut pas distinguer un constat qualifié d'un constat qui ne l'est pas ; normalement vide. |
| `services` | array | Services réseau installés avec `{ name, installed, active, risk, ports }`. **`ports` est un objet indexé par numéro de port**, pas une liste : `{ "22": { "exposure": "open_world" } }`. |
| `open_ports` | array | Ports en écoute sur `0.0.0.0` avec `{ port, address, process }` (filtré) |
| `open_ports_all` | array | Tous les ports en écoute, y compris bound localhost (nouveau en v2) |
| `firewall_drivers` | object | Détection bypass UFW : docker, libvirt, nftables, ip_forward, etc. Nommé `firewall_stack` avant la v0.9.0 ; un consommateur lisant encore l'ancien nom prend un `KeyError`. |
| `deductions_raw` | array | Toutes les déductions, y compris les caps synthétiques à 0 points (nouveau en v2) |
| `hardening` | object | Flags sysctl/AppArmor (uniquement quand collectés) |
| `ipv6` | object | Cohérence pile IPv6 (uniquement quand collectée) |

En mode complet, `network_context` porte additionnellement `interfaces` / `connections_count` / `top_remote_ips` — une **extension additive** de l'objet, pas un swap de type.

### Schémas retirés (v1, v2) — ce qui change vs le v3 actuel

v1 (v0.6.x, opt-in `--json-v1`) a été retiré en v0.9.0 ; v2 (v0.7.0) a été retiré en v0.12.0. Différences notables vs le layout **v3** actuel :

| Champ | v1 | v2 | v3 (actuel) |
|---|---|---|---|
| `schema_version` | `"1"` | `"2"` | `"3"` |
| `timestamp` | présent | renommé `timestamp_utc` | `timestamp_utc` |
| `alerts` / `warnings` | présents (compteurs int) | présents (compteurs int) | renommés `alert_count` / `warning_count` |
| `info_count` | absent | présent | présent |
| `network_context` | string en mode court ; dict en complet | toujours dict | toujours dict |
| `posture_escalation` | absent | présent | présent |
| `deductions_raw` / `open_ports_all` | absent | présent (complet) | présent (complet) |
| `domain_scores[d]` | `{ score, label }` | `{ score, label, deductions }` | `{ score, label, deductions, active, reason }` |

### Guide de migration (→ v3)

Pour la plupart des consommateurs la migration est mécanique :

| Si ton ancien code lit… | …en v3 utilise |
|---|---|
| `data["alerts"]` (compteur int v1/v2) | `data["alert_count"]` |
| `data["warnings"]` (compteur int v1/v2) | `data["warning_count"]` |
| `data["timestamp"]` (v1) | `data["timestamp_utc"]` |
| `data["network_context"]` (string v1) | `data["network_context"]["context"]` |
| `data["domain_scores"]["ssh"]["score"]` | inchangé |
| (autre) | inchangé — v3 est additif au-delà des renommages ci-dessus |

Fige-toi explicitement sur le majeur actuel :

```bash
sudo bob --json | jq 'if .schema_version == "3"
  then { alerts: .alert_count, warnings: .warning_count, score }
  else error("schema_version \(.schema_version) non supporté — attendu 3")
  end'
```

### Exemple de matching stable (indépendant de la locale)

```bash
# Matcher un finding spécifique par clé, indépendamment de la locale et de la version schema
sudo bob --json | jq '.deductions[] | select(.key == "firewall.logging_off")'
```

Les `findings[*].key` et `deductions[*].key` font partie du jeu de clés `--explain` — elles ne changeront pas sans bump majeur du schéma.

### Audit EXPLAIN_KEYS

À partir de v0.11.x, le set de clés `--explain` contient **194 clés** réparties sur **50 préfixes**. La convention de nommage canonique est appliquée par `tests/test_explain_naming_convention.py` :

- **Pattern :** `<prefix>.<finding_id>` (un seul point, snake_case)
- **Exceptions :** `file_perms.<path>.<finding_id>` (segments de chemin intermédiaires) et `services.{exposure,state}.<finding_id>` (taxonomie à deux niveaux), toutes deux résolues par `bob.explain.normalize_key`
- **Pas de retrait :** une fois publiée, une clé reste callable pendant la durée de vie du `schema_version` majeur
- **Aliases :** les renommages de clés passent par `EXPLAIN_KEY_ALIASES` pour la rétrocompatibilité
- **Ajouts :** de nouvelles clés peuvent être ajoutées dans n'importe quel minor
- **Garde de couverture :** tout finding WARN/ALERT émis par `bob/checks/*.py` doit avoir une entrée `EXPLAIN_KEYS` ou figurer dans `tests/test_explain_coverage.py::_KNOWN_GAPS` (actuellement vide — le drift batch v0.8.0 a comblé 51 entrées manquantes)

Vocabulaire des préfixes (50 préfixes, alphabétique) : `auditd, auth_log, backup, clamav, cloud_context, container_security, cron, ddns, disk, docker, docker_hardening, fail2ban, file_integrity, file_perms, firewall, firewall_drivers, firewall_iptables, firewall_rules, firmware, hardening, ipv6, kernel_hardening, kernel_modules, log_rotation, logs, mac_policy, memory, network_context, ntp, password_policy, plugin, ports, prerequisites, raspberry_pi, risk, rootkit, samba, secure_boot, services, services_health, smtp, socket_units, ssh, ssl_certs, suid_audit, systemd_timers, umask, updates, user_accounts, virt`.

Ajouter un nouveau préfixe dans une release future fait échouer `TestExplainPrefixDiscipline::test_key_prefix_is_known` jusqu'à ce que le mainteneur update explicitement `KNOWN_PREFIXES` — surfaçant l'ajout comme décision délibérée en code review.

Historique de référence : audit v0.7.0 = 117 clés / 30 préfixes / 100 % de conformité de nommage. Le drift batch v0.8.0 a ajouté 51 entrées explain pour des findings WARN/ALERT jusque-là non couverts, introduisant 15 nouveaux préfixes (`backup, ddns, docker, fail2ban, firewall_stack, iptables_nft, log_rotation, logs, mac_policy, network_context, ntp, ports, rootkit, services, smtp`).

---

## Politique de support Python

> **Engagement public stable** — ces règles régissent quand BOB abandonne le support d'un ancien Python.

BOB supporte les versions Python **N et N-2**, où **N** est la stable upstream actuelle. À partir de v0.7.0 :

| Python | Statut |
|---|---|
| 3.14 | ✅ supporté (ajouté en v0.7.0 — ladder étape 1 pour drop 3.10) |
| 3.13 | ✅ supporté |
| 3.12 | ✅ supporté (cible de développement actuelle, CI par défaut) |
| 3.11 | ✅ supporté |
| 3.10 | ✅ supporté (le plus ancien — drop prévu post-upstream EOL 2026-10) |
| 3.9  | ❌ end of life (abandonné en v0.2.3) |

Ladder de dépréciation Python 3.10 (en cours à partir de v0.7.0) :
- **v0.7.0 — Ladder étape 1** ✓ : 3.10 et 3.14 en CI pour valider la compatibilité avant.
- **Prochaine release minor BOB — Ladder étape 2** : annonce de la dépréciation 3.10 dans le changelog et bannière `--help`.
- **Release minor BOB suivante (post-2026-10) — Ladder étape 3** : retrait 3.10 de la CI, bump `requires-python` dans `pyproject.toml`.

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
