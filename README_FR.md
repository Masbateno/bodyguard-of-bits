*[Read in English](README.md)*

# BOB — Bodyguard Of Bits

**Auditeur de durcissement Linux pour les admins qui lisent vraiment la sortie.**

BOB est un outil d'audit de sécurité et de durcissement Linux en ligne de commande. Il exécute 38 sections de vérification sur 7 domaines de score, mappe les résultats aux sections du benchmark CIS quand applicable, et vous dit non seulement *ce qui ne va pas* — mais *pourquoi c'est important* et *comment y remédier avec des commandes concrètes*.

---

## Pour qui

- Admins système qui font des revues de durcissement périodiques
- Power users qui veulent plus qu'un score et une liste de flags
- Quiconque en a assez des outils d'audit bruyants et sans suite

BOB n'est pas un scanner. Il n'exploite pas, ne sonde pas, ne devine pas. Il évalue de façon déterministe votre configuration contre les benchmarks CIS et les bonnes pratiques établies.

---

## Pourquoi BOB ?

Lynis et OpenSCAP sont des outils solides et éprouvés — si vous avez besoin d'une couverture de conformité large ou de workflows de certification formels, ce sont les bons choix.

BOB répond à un besoin différent : **du durcissement pratique pour les admins qui ont besoin d'agir sur les résultats, pas de les archiver**. Chaque résultat est accompagné d'une explication en langage clair et d'une commande de remédiation prête à l'emploi. Le score de sécurité est contextuel — une machine directement exposée sur internet est jugée plus sévèrement qu'une machine derrière NAT. La sortie est conçue pour être lue dans un terminal, pas classée.

Si vous utilisez déjà Lynis, BOB n'est pas un remplacement — c'est un autre angle de lecture, axé sur ce qu'il faut faire ensuite.

---

## Ce que BOB est — et ce qu'il n'est pas

**BOB est** un auditeur de durcissement (hardening). Il évalue l'hygiène de configuration vs les benchmarks CIS et les bonnes pratiques établies, **modulée par le profil d'audit actif et le contexte réseau détecté**. Le score reflète *l'hygiène de configuration sous les hypothèses affichées* — pas un verdict de sécurité absolu.

**BOB n'est pas :**

- un scanner de vulnérabilités — il ne sonde pas de bases CVE, ne fingerprinte pas les versions logicielles vs des exploits connus, et ne teste pas les chemins d'exploitation (utilisez OpenVAS, Nessus, etc.) ;
- un moteur d'analyse de menaces (threat modeling) — il n'énumère pas les chemins d'attaque, ne teste pas la joignabilité depuis l'extérieur de l'hôte, et ne simule pas les scénarios de compromission (utilisez des scanners externes, du red-team tooling, des équipes sécurité) ;
- un système de verdict autonome — un score propre signifie *"hygiéniquement configuré pour le profil choisi dans le contexte réseau détecté"*, pas *"impossible à compromettre"*. Une interprétation humaine est requise pour traduire le verdict en risque opérationnel.

**Conséquences concrètes :**

- Un score 10/10 sur un poste de travail en LAN ne signifie **pas** un 10/10 sur le même hôte déplacé sur un cloud public — re-auditer avec le profil approprié.
- Un finding marqué `improvement` au lieu de `action` reflète le contexte réseau (ex. l'authentification SSH par mot de passe est une hygiène acceptable sur un hôte LAN-only, mais à durcir avant d'exposer l'hôte directement sur internet).
- Le profil d'audit (`server` / `workstation` / `container`) encode le modèle de menace. Changer de profil change le verdict — c'est par design.
- La détection de contexte réseau (NAT / IP publique / état des interfaces) est **heuristique**, pas un probing actif de joignabilité. Elle indique ce que BOB infère depuis le système local, pas ce qu'un attaquant observerait de l'extérieur.

Un mode CIS strict (sans modulation contextuelle) est prévu sur la roadmap.

---

## Installation

> **Sécurité d'exécution** : BOB est en lecture seule. Il n'exécute que des commandes inoffensives (`ss`, `dpkg-query`, `systemctl status`, `sysctl -n`, `ufw status`, etc.) et n'écrit qu'à `~/.config/bob` et son répertoire de logs. Le mode optionnel `--fix --apply` demande confirmation avant chaque correction ; rien d'autre ne modifie l'état du système. Un audit typique se termine en moins de 5 secondes.

### Prérequis

`pipx` (installateur d'apps Python isolées) :

```bash
sudo apt install pipx && pipx ensurepath
```

> Ouvrez un nouveau terminal après `pipx ensurepath` pour que le changement de `PATH` soit pris en compte.

### Installer BOB

```bash
pipx install bodyguard-of-bits
```

---

## Activer `sudo bob` + complétion bash

pipx installe le binaire `bob` dans `~/.local/bin/`, qui **n'est pas** dans le `PATH` restreint de sudo. Lancez `--install-completion` une fois avec le chemin absolu — il crée le lien symbolique `/usr/local/bin/bob` et installe le script de complétion bash :

```bash
sudo ~/.local/bin/bob --install-completion
source /etc/bash_completion.d/bob
```

Après cette étape, `sudo bob` fonctionne normalement et `bob --<TAB>` complète les options.

---

## Désinstaller

```bash
pipx uninstall bodyguard-of-bits
```

---

## Démarrage rapide

```
sudo bob                          # audit complet, profil serveur
sudo bob --verbose                # refs CIS et commandes de remédiation par résultat
sudo bob -d                       # sortie en français
sudo bob --profile workstation    # profil workstation
sudo bob --check ssh,hardening    # uniquement les domaines sélectionnés
sudo bob --format json > out.json # sortie machine
bob --explain ssh.password_auth   # expliquer un résultat (sans sudo)
```

---

## Aperçu de la sortie

```
$ sudo bob -d

╔══════════════════════════════════════════════════════════════════════════════╗
║                            — Bodyguard Of Bits —                             ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  BOB v0.13.1  │  Auditeur de durcissement Linux                              ║
║  Système       : Linux Mint 22.3                                             ║
║  Noyau         : 6.17.0-23-generic                                           ║
║  UFW           : v0.36.2                                                     ║
╚══════════════════════════════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━ DURCISSEMENT SYSTÈME ━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✔ [OK]   Protection SYN flood active (tcp_syncookies=1)
✔ [OK]   ASLR entièrement activé (randomize_va_space=2)
⚠ [WARN] Le système envoie des redirections ICMP — exploitable pour du MITM
   → sudo sysctl -w net.ipv4.conf.all.send_redirects=0
   [CIS:3.3.2]
   ? bob --explain hardening.send_redirects

╔══════════════════════════════════════════════════════════════════════════════╗
║  Score de sécurité : 8/10  ↑ +1                                              ║
║  Niveau de risque  : ✔ FAIBLE                                                ║
║  Pare-feu & Services  10/10  ██████████                                      ║
║  SSH                   7/10  ███████░░░                                      ║
║  Durcissement          4/10  ████░░░░░░                                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

Chaque WARN/ALERT affiche une référence CIS (quand applicable), une commande de remédiation à copier-coller, et un indicateur `--explain` qui pointe vers l'explication détaillée.

---

## Vérifications de sécurité — 38 sections de vérification, 7 domaines de score

| Domaine | Ce qu'il couvre |
|---------|----------------|
| **Pare-feu** | Règles UFW, iptables/nftables (quand UFW inactif), cohérence IPv6, exposition des ports |
| **SSH** | Durcissement sshd_config — PermitRootLogin, qualité des clés, timeouts, forwarding |
| **Durcissement noyau** | Paramètres sysctl, modules noyau, Secure Boot, firmware/microcode |
| **Services** | 38 services connus avec classification du risque ; détection du contournement pare-feu Docker |
| **Permissions fichiers** | Audit SUID/SGID, fichiers sensibles, sudoers |
| **Comptes utilisateurs** | Comptes expirés, politique de mots de passe, login.defs, PAM |
| **Mises à jour & détection** | Mises à jour apt, règles auditd, Fail2ban, ClamAV, AppArmor/SELinux, intégrité AIDE/Tripwire, rkhunter, SMART, firmware/microcode |
| **Opérations** | Rotation des logs, analyse auth.log, synchro NTP, expiration certificats TLS, timers systemd, Samba, tâches cron |
| **Réseau** | Contexte IP publique, détection du type de réseau (serveur/LAN/VPN), GeoIP optionnel |
| **Docker** | Durcissement du daemon, conteneurs privilégiés, montages sensibles |

---

## Mapping des benchmarks CIS

174 entrées : **107 CIS Ubuntu 22.04 · 7 CIS Docker · 60 bonnes pratiques**.

Chaque résultat avec un code CIS formel affiche `[CIS:X.Y.Z]` en ligne dans la boîte de synthèse.  
Le texte de référence complet est montré en mode `--verbose`.  
`--explain CLÉ` retourne le POURQUOI, le COMMENT, et la section CIS — en langage clair.

---

## --explain

```
bob --explain                     # TUI interactif — naviguez avec ↑↓, Entrée pour voir
bob --explain ssh.password_auth   # consultation directe
bob --explain list                # lister toutes les clés explicables
```

Sans sudo. Entièrement hors ligne — aucun appel externe ni collecte de données.

---

## Profils d'audit

| Profil | Cas d'usage |
|--------|------------|
| `server` | Par défaut — strict sur SSH, pare-feu, services |
| `desktop` | Assoupli pour les systèmes desktop — auth SSH par mot de passe tolérée, apps GUI non signalées, mécanismes de mise à jour manuels acceptés (~11 surcharges étendant `server`) |
| `workstation` | Profil business first-class depuis v0.8.1 (plus un alias vers `desktop`) — garde backup / auditd / MAC-enforce au niveau WARN tout en relâchant la même ergonomie SSH / clamav / rootkit / file-integrity que `desktop` |
| `container` | Étend `desktop` et saute les vérifications niveau hôte (modules noyau, durcissement noyau, secure boot, auditd, suid_audit, docker_audit, intégrité fichiers, rootkit) |

```
sudo bob --profile workstation
```

Profils personnalisés : `~/.config/bob/profiles/`

---

## Formats de sortie

```
sudo bob                          # terminal (défaut)
sudo bob --format json            # JSON
sudo bob --format csv             # CSV
sudo bob --format markdown        # Markdown
sudo bob --html                   # rapport HTML autonome
sudo bob --output-dir /var/reports --format json
```

---

## Automatisation

**Planification cron :**
```
sudo bob --install-cron           # assistant interactif
sudo bob --manage-cron            # gérer les jobs installés
```
Les jobs sont dans `/etc/cron.d/bob-{nom}`. Notification email si code de sortie > 0.

**Webhooks** (JSON générique ou Slack) :
```
sudo bob --webhook https://hooks.slack.com/...
```

**Historique et tendances des scores :**
```
sudo bob --history                # sparkline des scores passés
```

**Mode diff :**
```
sudo bob --diff                   # afficher uniquement les changements depuis la dernière baseline
```

**Décomposition du score :**
```
sudo bob --breakdown              # chemin complet de calcul du score (raccourci -B)
sudo bob -B
```

**Mode watch :**
```
sudo bob --watch=60               # relancer toutes les 60 secondes
```

---

## Services personnalisés

Déposez un fichier `.json` dans `~/.config/bob/services.d/` pour étendre le registre de services :

```json
{
  "id": "my_app",
  "name": "My App",
  "port": "9000/tcp",
  "risk": "medium"
}
```

---

## Liste blanche SUID

Sur Kali et autres distributions orientées sécurité, des outils légitimes sont livrés avec le bit SUID positionné. Déclarez les basenames approuvés ou des patterns glob dans `~/.config/bob/config.conf` pour les supprimer du warning "SUID inattendu" :

```
# ~/.config/bob/config.conf
suid_whitelist = kismet_cap_*, mon_outil_maison
```

Les patterns sont appliqués sur le basename du binaire via `fnmatch`. Les binaires supprimés sont rapportés en INFO pour que la liste blanche reste toujours visible.

---

## Codes de sortie

| Code | Signification |
|------|--------------|
| `0` | Score ≥ 7 — aucun problème significatif |
| `1` | Score 4–6 — avertissements présents |
| `2` | Score 1–3 — alertes présentes |
| `3` | Score 0 — problèmes critiques |
| `4` | Score sous le seuil `--target N` (gate personnalisable, ex : `bob --target 8` échoue en CI si le score < 8) |

---

## Prérequis

- Python 3.10+
- Root (`sudo`)
- `ss`, `systemctl` — standards sur la plupart des systèmes Linux

Optionnel : `geoip2` pour la géolocalisation IP (`pipx inject bodyguard-of-bits geoip2`)

---

## Compatibilité par distribution

| Niveau | Distros | État |
|--------|---------|------|
| **Tier 1** (production quotidienne) | Linux Mint 22.x, Debian 13 | Fonctionnalités complètes, validé sur matériel de production |
| **Tier 2** (validé par la CI) | Debian 12, Ubuntu 22.04/24.04/25.04, Kali Rolling, Fedora 41 | Smoke + audit hors ligne sur chaque PR ; pas de sentinelles locale, pas de traceback Python |
| **Tier 3** (fonctionne mais non testé) | Autres Debian / RHEL / SUSE / Arch-family | Best-effort ; les vérifications dégradent proprement |

Sur les distributions non-apt (Fedora, RHEL, openSUSE, Arch), les checks reposant sur `apt` (ex : mises à jour de sécurité en attente) émettent INFO au lieu de WARN — BOB ne consomme pas encore les métadonnées `dnf`/`zypper`/`pacman`. Les références CIS Ubuntu 22.04 restent émises tant que le contrôle sous-jacent (flags sysctl, config SSH, permissions de fichiers) est indépendant de la distribution.

---

## Voir aussi

- [Tutoriel — démarrer](DOCUMENTS/TUTORIAL_FR.md)
- [Référence technique complète](DOCUMENTS/README_TECH.md)
- [Journal des modifications](CHANGELOG_FR.md)
- [Guide développeur](DOCUMENTS/README_DEV_FR.md)
- [Guide d'automatisation](DOCUMENTS/AUTOMATION_FR.md)

---

## Licence

MIT — voir [LICENSE](LICENSE).

---

## Contribuer

Les issues et pull requests sont les bienvenues sur [github.com/Masbateno/bodyguard-of-bits](https://github.com/Masbateno/bodyguard-of-bits/issues). Pour les fonctionnalités significatives, ouvrir une issue d'abord pour discuter du périmètre est apprécié.

---

© 2026 Cédric Clauzel
