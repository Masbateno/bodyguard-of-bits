*[Read in English](README.md)*

# BOB — Bodyguard Of Bits

**Auditeur de durcissement Linux pour les admins qui lisent vraiment la sortie.**

BOB est un outil d'audit de sécurité et de durcissement Linux en ligne de commande. Il exécute 43 vérifications sur 9 domaines, mappe les résultats aux sections du benchmark CIS quand applicable, et vous dit non seulement *ce qui ne va pas* — mais *pourquoi c'est important* et *comment y remédier avec des commandes concrètes*.

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

## Installation

> **Sécurité d'exécution** : BOB est en lecture seule. Il n'exécute que des commandes inoffensives (`ss`, `dpkg-query`, `systemctl status`, `sysctl -n`, `ufw status`, etc.) et n'écrit qu'à `~/.config/bob` et son répertoire de logs. Le mode optionnel `--fix --apply` demande confirmation avant chaque correction ; rien d'autre ne modifie l'état du système. Un audit typique se termine en moins de 5 secondes.

```
pipx install bodyguard-of-bits
sudo bob
```

Complétion bash :
```
sudo bob --install-completion
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
║  BOB v0.4.6  │  Auditeur de durcissement Linux                               ║
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

## Vérifications de sécurité — 43 vérifications, 9 domaines

| Domaine | Ce qu'il couvre |
|---------|----------------|
| **Pare-feu** | Règles UFW, iptables/nftables (quand UFW inactif), cohérence IPv6, exposition des ports |
| **SSH** | Durcissement sshd_config — PermitRootLogin, qualité des clés, timeouts, forwarding |
| **Durcissement noyau** | Paramètres sysctl, modules noyau, Secure Boot, firmware/microcode |
| **Services** | 32 services connus avec classification du risque ; détection du contournement pare-feu Docker |
| **Permissions fichiers** | Audit SUID/SGID, fichiers sensibles, sudoers |
| **Comptes utilisateurs** | Comptes expirés, politique de mots de passe, login.defs, PAM |
| **Mises à jour & détection** | Mises à jour apt, règles auditd, Fail2ban, ClamAV, AppArmor/SELinux, intégrité AIDE/Tripwire, rkhunter, SMART, firmware/microcode |
| **Opérations** | Rotation des logs, analyse auth.log, synchro NTP, expiration certificats TLS, timers systemd, Samba, tâches cron |
| **Réseau** | Contexte IP publique, détection du type de réseau (serveur/LAN/VPN), GeoIP optionnel |
| **Docker** | Durcissement du daemon, conteneurs privilégiés, montages sensibles |

---

## Mapping des benchmarks CIS

137 entrées : **99 CIS Ubuntu 22.04 · 4 CIS Docker · 34 bonnes pratiques**.

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
| `workstation` | SSH assoupli, apps desktop non signalées |
| `desktop` | Workstation + vérifications spécifiques GUI |
| `docker` | Optimisé conteneurs, ignore les checks non pertinents |

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
