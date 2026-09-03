*[Read in English](TUTORIAL.md)*

# Tutoriel — démarrer avec BOB

Ce tutoriel te guide à travers ton premier audit BOB, de l'installation jusqu'à la compréhension de la sortie, l'application des correctifs et la mise en place d'audits récurrents. C'est le **chemin end-to-end premier-utilisateur** — pour la référence des commandes voir [`README_TECH_FR.md`](README_TECH_FR.md) ; pour les détails d'automation voir [`AUTOMATION_FR.md`](AUTOMATION_FR.md).

---

## Ce que fait BOB (en une phrase)

BOB lit la configuration hardening de ton système (SSH, firewall, services, paramètres kernel, …) et affiche un score avec les findings priorisés + des suggestions de correctifs.

Ce que BOB **n'est pas** : ce n'est pas un moteur de threat-modeling, pas un scanner de vulnérabilités actif, pas un système de verdict autonome. Le score est conditionné par le profil que tu choisis + le contexte réseau que BOB détecte — interprète-le comme tel. Voir `## Ce que BOB est / n'est PAS` dans [`../SECURITY_FR.md`](../SECURITY_FR.md) pour le cadrage complet.

---

## Étape 1 — installation

Le chemin d'install recommandé est `pipx` (isole BOB dans son propre venv, aucun impact sur ton Python système) :

```bash
sudo apt install pipx                       # Debian/Ubuntu/Mint
pipx install bodyguard-of-bits
pipx ensurepath                             # ajoute ~/.local/bin à PATH si nécessaire
exec bash                                   # reload shell
```

Pour Fedora/RHEL : `sudo dnf install pipx`. Pour Arch : `sudo pacman -S python-pipx`.

Vérifier :

```bash
bob --version                               # affiche "BOB v0.13.x"
```

### Faire fonctionner `sudo bob`

Par défaut `sudo` utilise un `PATH` restreint qui n'inclut pas `~/.local/bin`. Deux options :

**Option A — installer la completion (résout aussi `sudo bob`)**

```bash
sudo /home/$USER/.local/bin/bob --install-completion
exec bash
```

L'installeur de completion crée aussi un symlink dans `/usr/local/bin/bob`, qui est sur le `PATH` `sudo` par défaut. Après ça, `sudo bob` fonctionne directement et la tab-completion est activée pour `--check=<TAB>`, `--explain <TAB>`, `--profile=<TAB>`, etc.

**Option B — appeler avec le chemin complet** (pas d'install)

```bash
sudo /home/$USER/.local/bin/bob
```

---

## Étape 2 — ton premier audit

```bash
sudo bob
```

BOB tourne ~30 secondes (plus long la première fois, plus rapide ensuite). Tu verras :

1. **Des headers de section** au fur et à mesure que chaque domaine est checké (`SSH`, `Firewall`, `Services`, …) avec `✔` / `⚠` / `✖` par finding
2. **Une box résumé** à la fin avec le score (`/10`), le verdict (`hardening`, `acceptable`, `at risk`, `warning`, `critical`), le profil utilisé, et le contexte réseau détecté par BOB
3. **Une ligne footer "Hypothèses"** qui rend explicite quel profil + contexte ont produit ce score

Si `sudo bob` se plaint que le firewall n'est pas détectable, installe `ufw` (BOB cible le firewall par défaut Ubuntu/Debian ; firewalld n'est pas un substitut). Sur Fedora/Arch tu peux installer ufw en parallèle de firewalld.

### Lire le score

Le score commence à 10/10 et déduit selon les findings. Chaque finding a :

- Un **niveau** : OK (✔, vert) / WARN (⚠, jaune) / ALERT (✖, rouge)
- Une **clé** (ex. `ssh.password_auth_enabled`) — identifiant stable pour scripter + lookups `--explain`
- Un message court + optionnellement un hint `cmd=` si BOB sait comment fixer

Le verdict est conditionné par ton profil (`server` par défaut) — les profils desktop déduisent moins agressivement sur certaines préoccupations server-only (backup, auditd, MAC policy). Voir Étape 5 pour les profils.

---

## Étape 3 — comprendre n'importe quel finding

Si un finding n'a pas de sens pour toi, demande à BOB d'expliquer :

```bash
bob --explain ssh.password_auth_enabled
```

Pas de `sudo` requis — `--explain` est un lookup standalone, profile-aware. La sortie affiche :

- **Pourquoi c'est un risque** — impact concret + hypothèses threat model
- **Comment fixer** — commandes exactes (si connues) ou étapes manuelles
- **Scoring** — domain + tool cap (le pire que ton score peut déduire de ce finding)

Tu peux lister chaque clé explainable :

```bash
bob --explain list                          # 187 clés en v0.15.x
bob --explain                               # picker interactif (↑↓ naviguer, Enter voir, q quitter)
```

La tab-completion sur `bob --explain <TAB>` suggère les clés canoniques.

---

## Étape 4 — appliquer les fixes sans risque

BOB peut prévisualiser et appliquer les fixes pour les findings qui portent un template `cmd=`. Toujours prévisualiser d'abord :

```bash
sudo bob --fix                              # dry-run — montre ce qui serait appliqué
```

Chaque ligne est soit ✓ (sera appliqué) soit ✗ (manuel — BOB refuse l'auto-fix). Le dry-run ne modifie jamais ton système.

Quand tu es prêt :

```bash
sudo bob --fix --apply                      # confirmation interactive par fix
sudo bob --fix --apply -y                   # batch mode (audit trail sauvé dans ~/.config/bob/fix-audit.log)
```

Re-lance `sudo bob` pour confirmer que le score est remonté.

---

## Étape 5 — choisir le bon profil

BOB ship 4 profils :

| Profil | Quand utiliser | Déduit sur |
|---|---|---|
| `server` (défaut) | serveurs production, edge nodes | attentes hardening complètes y compris backup, auditd, MAC policy |
| `desktop` | laptop personnel, workstation | relâche les exigences backup + audit logging ; SSH + firewall restent strict |
| `workstation` | workstation business partagée/multi-user | strict sur backup + auditd + MAC policy ; relâché sur l'ergonomie personal-use |
| `container` | audit containerisé (ex. images base Docker) | skip les checks kernel-hardening non pertinents dans un container |

Choisis une fois par host :

```bash
sudo bob -p desktop                         # ENREGISTRE aussi desktop comme défaut
sudo bob -p desktop -d                      # idem, avec rapport détaillé
sudo bob                                    # les runs suivants réutilisent le profil
```

**BOB mémorise ton choix.** Un `-p NOM` valide est écrit dans
`~/.config/bob/config.conf` sous la clé `audit_profile=` et devient le défaut de
toutes les exécutions suivantes — inutile de répéter l'option, ni en cron ni
ailleurs. Pour en changer, repasse `-p` ; pour vérifier le profil courant,
`bob --format=json | jq -r .profile`, ou lis la ligne `Profil d'audit :` en tête
d'un audit normal.

Un nom invalide n'est *pas* enregistré : BOB avertit et retombe sur le défaut,
sans toucher à ton vrai profil.

---

## Étape 6 — silencer les findings bruyants

Si un finding ne s'applique pas à ton environnement, supprime-le au lieu d'ignorer le warning :

```bash
bob --ignore ssh.x11_forwarding             # ajoute à ~/.config/bob/ignore.yml
bob --unignore ssh.x11_forwarding           # retire
sudo bob --show-ignored                     # voir les findings mutés en gris à côté de la sortie normale
```

Un finding ignoré déduit zéro point **et disparaît de la sortie** — c'est
l'objet même de l'option. Passe `--show-ignored` pour lister les findings mutés
en gris à côté de la sortie normale. Préférable à `--skip=`, qui retire l'audit
de la section entière plutôt qu'un seul finding.

(Avant la v0.14.1, le score et les compteurs JSON honoraient `--ignore` mais le
finding continuait de s'afficher intégralement ; si tu l'avais constaté, c'est
corrigé.)

---

## Étape 7 — automatiser les audits récurrents

```bash
sudo bob --install-cron
```

Le wizard te guide à travers nom → planning → heure → email optionnel. Fichiers créés :

- `/usr/local/bin/bob-{nom}` — wrapper script qui appelle BOB avec ta config sauvegardée
- `/etc/cron.d/bob-{nom}` — entry cron système

Pour l'automation incident-response, configure un webhook dans `~/.config/bob/config.conf` :

```bash
bob --webhook=https://hooks.slack.com/services/T00/B00/XXXX
bob --test-webhook                          # POST un payload smoke-test (pas d'audit) et exit
```

`--test-webhook` vérifie que l'URL + le récepteur sont joignables avant que le prochain audit planifié ne tire. Le payload smoke est tagué `bob_smoke_test` pour que ton récepteur puisse filtrer.

Voir [`AUTOMATION_FR.md`](AUTOMATION_FR.md) pour le setup cron + webhook complet.

---

## Étape 8 — suivre les changements dans le temps

Après ton premier audit, BOB stocke un baseline dans `~/.config/bob/baseline.json`. Les audits suivants comparent contre lui :

```bash
sudo bob --diff                             # afficher seulement ce qui a changé depuis le dernier audit
sudo bob --history                          # sparkline des 10 derniers scores
sudo bob --reset-baseline                   # reset (prochain audit démarre un nouvel historique)
```

Combiné avec `--watch` tu obtiens une vue live-refresh :

```bash
sudo bob --watch                            # re-run toutes les 60 s
sudo bob --watch=30                         # intervalle custom
```

`Ctrl+C` quitte.

---

## Étape 9 — formats de sortie pour consumers machine

BOB peut émettre JSON / CSV / Markdown / HTML pour les pipelines :

```bash
sudo bob --format=json | jq '.score'        # score en JSON
sudo bob --format=csv  > audit.csv          # spreadsheet-friendly
sudo bob --format=markdown > /tmp/audit.md  # .md humain-lisible (stdout)
sudo bob --format=html     > /tmp/audit.html # rapport HTML (stdout)
```

`-J` et `-j` sont des raccourcis pour `--format=json-full` / `--format=json`. Combine avec `--min-level=warn` pour filtrer.

Deux champs JSON valent d'être connus si tu rediriges la sortie quelque part (tous deux depuis la v0.14.1) :

```bash
sudo bob --format=json | jq -r .profile              # quel profil a produit ces chiffres
sudo bob --format=json | jq -r '.degraded_sections'  # [] sur une exécution saine
```

`degraded_sections` liste les sections dont le check a échoué et qui ont été
écartées au lieu d'interrompre tout l'audit. Le code de sortie reste piloté par
les findings réels : c'est donc le seul endroit où un pipeline peut voir que
l'audit était **incomplet**.

---

## Scénarios courants

### « Je veux juste un score sans bruit »

```bash
sudo bob -q                                 # silencieux — le code de sortie donne le verdict
echo $?                                     # 0=OK / 1=WARN / 2=ALERT / 3=erreur / 4=sous --target
```

Wire `-q` dans un cron job + check du code de sortie pour l'alerting le plus simple possible.

### « Je veux verrouiller un score minimum »

```bash
sudo bob --target=8                         # affiche gap ou success dans le résumé
# code de sortie 4 si score < 8
```

Utile en CI pour faire échouer un build si un système passe sous ta barre.

### « Je veux un audit en français »

```bash
sudo bob --french                           # raccourci pour --lang=fr
sudo bob --lang=fr                          # explicite
```

Toute la sortie (terminal, `--help`, .log, messages detail JSON, payloads webhook, entries explain) est localisée — 2227 clés × 2 locales en v0.15.3 — **à une exception que vous verrez à l'écran : les 27 libellés de services porteurs de prose anglaise** (`Samba (Windows file sharing)`, `Apache Web Server`, …) restent en anglais à dessein, comme expliqué ci-dessous. `--help` a rejoint la liste en v0.15.3 : il rendait de l'anglais sous `--french` depuis la v0.1.0.

Trois choses restent anglaises à dessein, et un diff bilingue de la sortie d'audit en v0.15.4 a confirmé que ce sont les seules : les **commandes shell** des lignes de remédiation (une commande n'est pas de la prose), les **références CIS** portant un code numéroté (décision v0.11.2 — les 60 non codées, elles, *sont* traduites), et les **38 libellés de services** — dont 27 portent de la prose anglaise descriptive, comme `Samba (Windows file sharing)` ou `Apache Web Server` — traités comme des noms de produits. Ces libellés servent aussi de clé aux entrées `service_risk.*` et entrent dans la ligne de base d'audit : les traduire à la source renommerait 114 entrées de locale et ferait apparaître des changements fantômes dans `--diff` au changement de langue.

---

## Lecture suivante

- [`README_TECH_FR.md`](README_TECH_FR.md) — référence complète des commandes avec chaque flag + codes de sortie
- [`AUTOMATION_FR.md`](AUTOMATION_FR.md) — deep-dive cron + webhook + notification email
- [`../SECURITY_FR.md`](../SECURITY_FR.md) — threat model, ce que BOB est / n'est PAS, env vars trap-door
- [`../CHANGELOG_FR.md`](../CHANGELOG_FR.md) — historique des releases avec highlights par-version
- `bob --explain list` — chaque finding que BOB sait expliquer, browsable dans le picker curses

Si tu rencontres un bug ou veux qu'un finding soit ajouté, ouvre une issue sur [https://github.com/Masbateno/bodyguard-of-bits](https://github.com/Masbateno/bodyguard-of-bits).

---

© 2026 Cédric Clauzel
