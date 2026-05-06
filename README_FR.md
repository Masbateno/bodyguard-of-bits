*[Read in English](README.md)*

# BOB — Bodyguard Of Bits

**Auditeur de durcissement Linux pour les admins qui lisent vraiment la sortie.**

BOB est un outil d'audit de sécurité et de durcissement Linux en ligne de commande. Il exécute 46 vérifications sur 9 domaines, mappe les résultats aux sections du benchmark CIS quand applicable, et vous dit non seulement *ce qui ne va pas* — mais *pourquoi c'est important* et *comment y remédier avec des commandes concrètes*.

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

## Vérifications de sécurité — 46 checks, 9 domaines

| Domaine | Ce qu'il couvre |
|---------|----------------|
| **Pare-feu** | Règles UFW, iptables/nftables (quand UFW inactif), cohérence IPv6, exposition des ports |
| **SSH** | Durcissement sshd_config — PermitRootLogin, qualité des clés, timeouts, forwarding |
| **Durcissement noyau** | Paramètres sysctl, modules noyau, Secure Boot, firmware/microcode |
| **Services** | 32 services connus avec classification du risque ; détection du contournement pare-feu Docker |
| **Permissions fichiers** | Audit SUID/SGID, fichiers sensibles, sudoers |
| **Comptes utilisateurs** | Comptes expirés, politique de mots de passe, login.defs, PAM |
| **Système** | Mises à jour apt, rotation des logs, analyse auth.log, NTP, Fail2ban, auditd, ClamAV, AppArmor/SELinux, SMART, expiration certificats TLS, timers systemd, Samba, tâches cron |
| **Réseau** | Contexte IP publique, détection du type de réseau (serveur/LAN/VPN), GeoIP optionnel |
| **Docker** | Durcissement du daemon, conteneurs privilégiés, montages sensibles |

---

## Mapping des benchmarks CIS

133 entrées : **99 CIS Ubuntu 22.04 · 4 CIS Docker · 34 bonnes pratiques**.

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

## Codes de sortie

| Code | Signification |
|------|--------------|
| `0` | Score ≥ 7 — aucun problème significatif |
| `1` | Score 4–6 — avertissements présents |
| `2` | Score 1–3 — alertes présentes |
| `3` | Score 0 — problèmes critiques |
| `4` | Score sous le seuil `--target N` |

---

## Prérequis

- Linux — testé sur Linux Mint 22.3, Debian 13.4.0
- Python 3.10+
- Root (`sudo`)
- `ss`, `systemctl` — standards sur la plupart des systèmes Debian-based

Optionnel : `geoip2` pour la géolocalisation IP (`pipx inject bodyguard-of-bits geoip2`)

---

## Voir aussi

- [Référence technique complète](DOCUMENTS/README_TECH.md)
- [Journal des modifications](CHANGELOG_FR.md)
- [Guide développeur](DOCUMENTS/README_DEV_FR.md)
- [Guide d'automatisation](DOCUMENTS/AUTOMATION_FR.md)
