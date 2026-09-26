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
bob --version                               # affiche "bob 0.21.x" (SemVer nu, sans « v »)
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

BOB prend de quelques secondes à deux ou trois minutes — environ 9 s sur un desktop à SSD rapide, mais ~40 s à plus de 2 minutes sur un disque lent (mécanique) ou une petite carte comme un Raspberry Pi Zero. Ça dépend du disque, du CPU et du nombre de services installés, pas seulement de l'architecture. Tu verras :

1. **Des headers de section** au fur et à mesure que chaque domaine est checké (`SSH`, `Firewall`, `Services`, …) avec `✔` / `⚠` / `✖` par finding
2. **Une box résumé** à la fin avec le score (`/10`), le verdict (`hardening`, `acceptable`, `at risk`, `warning`, `critical`), le profil utilisé, et le contexte réseau détecté par BOB
3. **Une ligne footer "Hypothèses"** qui rend explicite quel profil + contexte ont produit ce score

Si `sudo bob` se plaint que le firewall n'est pas détectable, installe `ufw` (BOB cible le firewall par défaut Ubuntu/Debian ; firewalld n'est pas un substitut). Sur Fedora/Arch tu peux installer ufw en parallèle de firewalld.

### Lire le score

Le score commence à 10/10 et déduit selon les findings. Chaque finding a :

- Un **niveau** : OK (✔, vert) / WARN (⚠, jaune) / ALERT (✖, rouge)
- Une **clé** (ex. `ssh.password_auth`) — identifiant stable pour scripter + lookups `--explain`
- Un message court + optionnellement un hint `cmd=` si BOB sait comment fixer

Le verdict est conditionné par ton profil (`server` par défaut) — les profils desktop déduisent moins agressivement sur certaines préoccupations server-only (backup, auditd, MAC policy). Voir Étape 5 pour les profils.

---

## Étape 3 — comprendre n'importe quel finding

Si un finding n'a pas de sens pour toi, demande à BOB d'expliquer :

```bash
bob --explain ssh.password_auth
```

Pas de `sudo` requis — `--explain` est un lookup standalone, profile-aware. La sortie affiche :

- **Pourquoi c'est un risque** — impact concret + hypothèses threat model
- **Comment fixer** — commandes exactes (si connues) ou étapes manuelles
- **Scoring** — domain + tool cap (le pire que ton score peut déduire de ce finding)

Tu peux lister chaque clé explainable :

```bash
bob --explain list                          # 206 clés en v0.21.x, groupées par famille CIS
bob --explain                               # picker interactif (↑↓/jk, PgUp/PgDn, g/G, Entrée, l langue, q quitter)
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

Re-lance `sudo bob` pour voir ce qui a changé. Le score remonte le plus
souvent, mais pas toujours : installer un paquet peut *révéler* un constat que
son absence masquait — `sudo apt install -y ufw` efface « UFW n'est pas
installé » et lève « UFW est installé mais inactif », qui coûte davantage.
C'est l'audit qui dit la vérité sur une machine désormais un cran plus loin,
pas un correctif qui a échoué.

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

Le wizard te guide à travers nom → planning → heure → email optionnel → profil → langue → sondes sortantes. Fichiers créés :

- `/usr/local/bin/bob-{nom}` — wrapper script qui appelle BOB avec le profil, la langue et la posture réseau que tu as choisis. Ces trois-là sont demandés parce qu'un cron s'exécute en root : avant la v0.16.1 le script lisait la config sauvegardée de *root*, pas la tienne, si bien que l'audit nocturne d'un opérateur `desktop` était silencieusement noté en `server` — et comme le profil pilote le code de sortie, il décidait aussi si l'email partait
- `/etc/cron.d/bob-{nom}` — entry cron système

### S'assurer que la notification peut réellement arriver

La dernière ligne du wizard te dit qui entendra parler de cette tâche. Lis-la :
trois de ses cinq réponses sont *personne*.

Le script généré notifie **par email et par rien d'autre**. Si tu passes
l'adresse, l'audit tourne quand même et écrit quand même son rapport dans ton
répertoire de logs — mais rien ne te parvient, et jusqu'à la v0.17.0 rien ne le
disait. Un webhook enregistré dans la config de **root** est l'autre sortie, et
un audit programmé le déclenche bien, mais `--offline` supprime le POST.

Si tu as donné une adresse, le wizard te dit si un binaire `sendmail` existe.
C'est tout ce qu'il peut te dire, et ce n'est pas assez : un Postfix installé
depuis la distribution et jamais pourvu d'un relais satisfait à ce test et
jette chaque message. Établis le reste en envoyant :

```bash
bob --test-email                            # un vrai message, par le transport du cron
```

Il emprunte le même chemin de code que la tâche programmée : un succès ici
signifie que le mail de la tâche prendrait la même route. Il sort en non-zéro
quand `sendmail` refuse le message — l'échec autrement invisible, puisque la
façon de l'apprendre serait le mail qui n'arrive jamais.

*Accepté n'est pas délivré.* Une sortie 0 signifie que le MTA a pris le
message ; un relais ou un filtre anti-spam peut encore le jeter. Vérifie la
boîte de réception une fois, puis fais confiance à la planification.

**Pas de MTA sur l'hôte ?** Deux options honnêtes :

| | |
|---|---|
| `postfix` | Un serveur de mail complet. Choisis *« Site Internet »* si l'hôte peut émettre directement, ou *« Système satellite »* en nommant le relais de ton fournisseur si le port 25 est bloqué en sortie — ce qu'il est sur la plupart des connexions résidentielles et chez beaucoup d'hébergeurs. |
| `msmtp` + `msmtp-mta` | Relaie via un compte mail existant (un `~/.msmtprc` avec ton hôte SMTP, l'utilisateur et un mot de passe d'application). Bien plus léger que Postfix, et la bonne réponse pour un portable ou un petit VPS qui ne fait qu'émettre. |

Les noms de paquets varient selon la distribution, et la configuration du
relais aussi — le guide Postfix de [`AUTOMATION.md`](AUTOMATION.md) en est la
version longue, y compris la partie dont la plupart des gens ont réellement
besoin : relayer via un fournisseur parce que le port 25 est bloqué en sortie.

Ou renonce au mail et utilise un webhook, qui n'a besoin de rien de tout cela.

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

Le CSV porte une ligne par constat et, depuis la v0.18.0, sa dernière
colonne est `key` — le même identifiant que prennent `--explain` et
`--ignore`, et celui sur lequel une baseline est indexée. Utilise-la plutôt
que `message`, qui est de la prose traduite : elle change avec la langue et
avec les reformulations.

```bash
sudo bob --format=csv | awk -F, 'NR>1 && $10=="alert" {print $NF}'
```

Cet `awk` tient parce que `level` se trouve avant toute colonne de texte
libre et qu'une clé de constat ne contient jamais de virgule — dès que tu
touches à `message` ou `detail`, passe par un vrai lecteur CSV. Les quinze
colonnes qui précèdent `key` gardent leur position : un consommateur écrit
pour la v0.17.1 n'est pas affecté.


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

Toute la sortie (terminal, `--help`, .log, messages detail JSON, payloads webhook, entries explain) est localisée — 2606 clés × 2 locales en v0.21.1 — **à une exception que vous verrez à l'écran : les 27 libellés de services porteurs de prose anglaise** (`Samba (Windows file sharing)`, `Apache Web Server`, …) restent en anglais à dessein, comme expliqué ci-dessous. `--help` a rejoint la liste en v0.15.3 : il rendait de l'anglais sous `--french` depuis la v0.1.0.

Trois choses restent anglaises à dessein, et un diff bilingue de la sortie d'audit en v0.15.4 a confirmé que ce sont les seules : les **commandes shell** des lignes de remédiation (une commande n'est pas de la prose), les **références CIS** portant un code numéroté (décision v0.11.2 — les 87 non codées, elles, *sont* traduites), et les **38 libellés de services** — dont 27 portent de la prose anglaise descriptive, comme `Samba (Windows file sharing)` ou `Apache Web Server` — traités comme des noms de produits. Ces libellés servent aussi de clé aux entrées `service_risk.*` et entrent dans la ligne de base d'audit : les traduire à la source renommerait 114 entrées de locale et ferait apparaître des changements fantômes dans `--diff` au changement de langue.

---

## Lecture suivante

- [`README_TECH_FR.md`](README_TECH_FR.md) — référence complète des commandes avec chaque flag + codes de sortie
- [`AUTOMATION_FR.md`](AUTOMATION_FR.md) — deep-dive cron + webhook + notification email
- [`../SECURITY_FR.md`](../SECURITY_FR.md) — threat model, ce que BOB est / n'est PAS, env vars trap-door
- [`../CHANGELOG_FR.md`](../CHANGELOG_FR.md) — historique des releases avec highlights par-version
- `bob --explain list` — chaque finding que BOB sait expliquer, groupé par famille de benchmark CIS (CIS Ubuntu, CIS Docker, Bonne pratique, …) ; browsable dans le picker curses

Si tu rencontres un bug ou veux qu'un finding soit ajouté, ouvre une issue sur [https://github.com/Masbateno/bodyguard-of-bits](https://github.com/Masbateno/bodyguard-of-bits).

---

© 2026 Cédric Clauzel
