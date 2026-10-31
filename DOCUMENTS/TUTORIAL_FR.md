*[Read in English](TUTORIAL.md)*

# Tutoriel — démarrer avec BOB

Ce tutoriel te guide à travers ton premier audit BOB, de l'installation jusqu'à la lecture de la sortie, l'application des correctifs et la mise en place d'audits récurrents. C'est le **parcours complet d'un premier utilisateur** — pour la référence des commandes voir [`README_TECH_FR.md`](README_TECH_FR.md) ; pour le détail de l'automatisation voir [`AUTOMATION_FR.md`](AUTOMATION_FR.md).

---

## Ce que fait BOB (en une phrase)

BOB lit la configuration de durcissement de ton système (SSH, pare-feu, services, paramètres du noyau, …) et affiche un score avec des constats classés par priorité et des suggestions de correctifs.

Ce que BOB **n'est pas** : ce n'est pas un moteur de modélisation des menaces, pas un scanner de vulnérabilités actif, pas un système de verdict autonome. Le score dépend du profil que tu choisis et du contexte réseau que BOB détecte — interprète-le comme tel. Voir la section *Ce qu'est BOB* de [`../SECURITY_FR.md`](../SECURITY_FR.md) pour le cadrage complet.

---

## Étape 1 — installation

La voie d'installation recommandée est `pipx` (qui isole BOB dans son propre environnement virtuel, sans toucher au Python du système) :

```bash
sudo apt install pipx                       # Debian/Ubuntu/Mint
pipx install bodyguard-of-bits
pipx ensurepath                             # ajoute ~/.local/bin au PATH si nécessaire
exec bash                                   # recharge le shell
```

Pour Fedora : `sudo dnf install pipx`. Pour Arch : `sudo pacman -S python-pipx`. Ailleurs, cherche `pipx` dans les dépôts de ta distribution : le nom du paquet et le dépôt qui le fournit varient.

Vérifier :

```bash
bob --version                               # affiche "bob X.Y.Z" (SemVer nu, sans « v »)
```

### Faire fonctionner `sudo bob`

Par défaut `sudo` utilise un `PATH` restreint qui n'inclut pas `~/.local/bin`. Deux options :

**Option A — installer la complétion (règle aussi `sudo bob`)**

```bash
sudo /home/$USER/.local/bin/bob --install-completion
exec bash
```

L'installeur de la complétion crée aussi un lien symbolique `/usr/local/bin/bob`, qui figure dans le `PATH` par défaut de `sudo`. Ensuite, `sudo bob` fonctionne directement et la complétion par tabulation est active pour `--check=<TAB>`, `--explain <TAB>`, `--profile=<TAB>`, etc.

**Option B — appeler BOB par son chemin complet** (sans rien installer)

```bash
sudo /home/$USER/.local/bin/bob
```

**Sur un hôte qui utilise `doas` au lieu de `sudo`** (Alpine, par exemple), utilise `doas` partout où ce tutoriel écrit `sudo`, avec le chemin complet de BOB tant que l'option A n'a pas créé le lien (`doas /home/$USER/.local/bin/bob --install-completion`). BOB trouve ton répertoire personnel grâce à la variable `SUDO_USER` de sudo et, depuis la 0.25.1, `DOAS_USER` de doas : tes réglages, ta liste d'exclusions, ta ligne de base et ton historique restent dans ton propre `~/.config/bob`. (Avant la 0.25.1, ils allaient dans `/root/.config/bob` sous doas, et aucun lien n'était créé ; mesuré sur Alpine 3.24.) Autre différence d'Alpine : BusyBox crond lit `/etc/crontabs/` et il n'y a pas de `/etc/cron.d`, donc `--install-cron` (étape 7) écrit la tâche comme un bloc repéré de la crontab de root, `/etc/crontabs/root`, sans toucher au reste du fichier (depuis la 0.26.0 ; la 0.25.1 refusait).

---

## Étape 2 — ton premier audit

```bash
sudo bob
```

Un audit dure de quelques secondes à quelques minutes : la durée dépend du disque, du processeur et du nombre de services installés. Le cadre de synthèse affiche la durée de l'exécution, inutile donc de la deviner. Tu verras :

1. **Un titre par domaine** (`PARE-FEU & RÉSEAU`, `EXPOSITION & SERVICES`, `CONTRÔLE D'ACCÈS`, …), un encadré par section en dessous, et une ligne par constat marquée `✔ [OK]`, `ℹ [INFO]`, `⚠ [ATTENTION]` ou `✖ [ALERTE]`
2. **Un cadre de synthèse** à la fin : le score sur 10 (écrit `≤ N/10` quand une section n'a pas pu être lue en entier — le score est alors un plafond), le niveau de risque (`FAIBLE`, `MOYEN`, `ÉLEVÉ` ou `CRITIQUE`), le contexte réseau détecté par BOB, le profil d'audit et la durée ; puis les constats à traiter en premier (*À corriger*), les *Améliorations possibles* et le détail du score
3. **Sous le cadre**, un rappel que le verdict dépend du profil et du contexte réseau affichés au-dessus, le score de chaque domaine, et une synthèse de la surface d'attaque

BOB lit UFW, firewalld, et un jeu de règles nftables ou iptables brut. Quand aucun d'eux ne filtre le trafic entrant, il lève *« Aucun pare-feu actif »* et propose l'outil de pare-feu de ta famille de distributions — `ufw` sur Debian, Ubuntu, Arch et Alpine, `firewalld` sur Fedora, RHEL et openSUSE — avec des commandes qui autorisent SSH avant que le pare-feu ne commence à filtrer. Sur Alpine avec awall installé, BOB nomme awall à la place : il dit quelles politiques sont activées, ou qu'aucune ne l'est, et n'imprime aucune commande, puisque le choix d'une politique te revient (0.26.0).

### Lire le score

Chaque domaine part de 10/10 et perd les points de ses constats ; le score global est la moyenne des domaines qui ont au moins un constat autre qu'INFO, arrondie, et maintenue à 9 dès que quelque chose a été déduit (10/10 est réservé à un audit sans rien à corriger). Deux constats plafonnent en outre leur domaine : un UFW installé mais inactif, et l'absence de tout pare-feu actif, maintiennent *Pare-feu & Réseau* à 3/10 (le second depuis 0.26.0). Chaque constat a :

- Un **niveau** : OK (✔, vert) / INFO (ℹ, cyan — signalé, ne coûte aucun point) / ATTENTION (⚠, jaune) / ALERTE (✖, rouge)
- Une **clé** (ex. `ssh.password_auth`) — identifiant stable pour les scripts, `--explain` et `--ignore` ; le cadre de synthèse l'affiche sur la ligne `? bob --explain CLÉ`
- Un message court et, dans le cadre de synthèse, la commande que BOB suggère — après `→` pour un correctif, après `ℹ` pour une commande qui ne fait que vérifier

Le verdict dépend de ton profil : `server` par défaut, ou `desktop` quand aucun profil n'est défini et que BOB trouve un gestionnaire d'affichage actif — il l'annonce dans une ligne INFO avant le début de l'audit. Le profil desktop ramène en INFO des constats qui pèsent moins sur une machine personnelle, comme l'absence de sauvegarde ou de règles auditd. Voir l'étape 5 pour les profils.

---

## Étape 3 — comprendre n'importe quel constat

Si un constat ne te parle pas, demande à BOB de l'expliquer :

```bash
bob --explain ssh.password_auth
```

Pas besoin de `sudo` — `--explain` est une consultation autonome, qui tient compte des profils. La sortie affiche :

- **Pourquoi c'est un risque** — l'impact concret
- **Comment corriger** — des commandes (quand elles sont connues) ou des étapes manuelles
- **Une ligne par profil** — s'il compte le constat en entier ou le ramène en INFO (les clés dotées d'un texte propre à chaque profil ont à la place une section par profil)
- **Notation** — le domaine où compte le constat, le plafond des trois familles d'outils (rootkit, ClamAV, intégrité des fichiers : au plus 1 point en tout pour chacune), et un renvoi vers `sudo bob --breakdown` pour sa contribution actuelle

Tu peux lister toutes les clés explicables :

```bash
bob --explain list                          # 235 clés en v0.28.x, groupées par famille CIS
bob --explain                               # sélecteur interactif (↑↓/jk, PgUp/PgDn, g/G, Entrée, Échap retour ; l langue et q quitter sur le premier écran)
```

La complétion par tabulation sur `bob --explain <TAB>` propose les clés canoniques.

---

## Étape 4 — appliquer les correctifs sans risque

BOB peut prévisualiser et appliquer les correctifs des constats accompagnés d'une commande de correction. Prévisualise toujours d'abord :

```bash
sudo bob --fix                              # simulation — montre ce qui serait appliqué
```

L'aperçu liste chaque correctif que BOB peut appliquer — le constat, puis la commande après `→` — et, à part, les commandes qu'il se contente d'afficher (des vérifications à lancer toi-même) et les constats qui demandent une correction manuelle. La simulation ne modifie jamais ton système.

Quand tu es prêt :

```bash
sudo bob --fix --apply                      # confirmation interactive pour chaque correctif
sudo bob --fix --apply -y                   # sans question — liste à la fin les commandes appliquées
```

Relance `sudo bob` pour voir ce qui a changé. Le score remonte le plus
souvent, mais pas toujours : installer un paquet peut *révéler* un constat que
son absence masquait. Sans aucun pare-feu, BOB lève « Aucun pare-feu actif » —
une ALERTE qui ne coûte aucun point ; une fois `sudo apt install -y ufw`
exécuté, le constat devient « Le pare-feu UFW est désactivé », qui maintient
le domaine *Pare-feu & Réseau* à 3/10. Les deux placent le niveau de risque à
`ÉLEVÉ` ou au-dessus. La baisse vient de ce plafond, pas d'un correctif raté :
activer UFW est l'étape suivante.

---

## Étape 5 — choisir le bon profil

BOB livre 4 profils :

| Profil | Quand l'utiliser | Ce qui change |
|---|---|---|
| `server` (défaut) | serveurs, et tout hôte que tu veux juger à plein | chaque constat à sa pleine sévérité |
| `desktop` | portable ou poste personnel — choisi automatiquement quand aucun profil n'est défini et qu'un gestionnaire d'affichage est actif | 35 constats ramenés en INFO, dont l'absence de sauvegarde, auditd, AppArmor sans profil en mode enforce, Secure Boot, les mises à jour automatiques, la fraîcheur des analyses rootkit / ClamAV / intégrité des fichiers, et l'authentification SSH par mot de passe et les redirections SSH ; l'état du pare-feu et la connexion root en SSH gardent leur pleine sévérité |
| `workstation` | poste partagé ou professionnel | les mêmes 30 assouplissements que `desktop`, sans les cinq qui portent sur la sauvegarde, auditd et l'application d'AppArmor, qui gardent leur pleine sévérité |
| `container` | un audit à l'intérieur d'un conteneur | étend `desktop` et saute 17 sections propres à l'hôte : durcissement sysctl, modules noyau, durcissement du noyau, Secure Boot, Raspberry Pi, auditd, audit SUID, durcissement Docker, rootkit, intégrité des fichiers, disque, mémoire, fail2ban, ClamAV, NTP, politique MAC et sauvegarde |

Choisis une fois par hôte :

```bash
sudo bob -p desktop                         # ENREGISTRE aussi desktop comme défaut
sudo bob -p desktop -d                      # idem, et enregistre le rapport complet dans un fichier journal
sudo bob                                    # les exécutions suivantes réutilisent le profil
```

**BOB mémorise ton choix.** Un `-p NOM` valide est écrit dans
`~/.config/bob/config.conf` sous la clé `audit_profile=` et devient le défaut de
tous les `sudo bob` suivants — inutile de répéter l'option. Une tâche cron ne le
lit pas : elle tourne en root, donc l'assistant lui demande son profil et
l'écrit dans le script de la tâche (étape 7), en présélectionnant le `-p` passé
à `--install-cron`, sinon ton profil enregistré, sinon `server`. Pour changer le profil enregistré, repasse
`-p` ; pour vérifier le profil courant, lis la ligne `Profil d'audit :` en tête
d'un audit normal, ou lance `sudo bob --format=json | jq -r .profile`.

Un nom invalide n'est *pas* enregistré : BOB avertit et mène cet audit avec
`server`, sans toucher à ton profil enregistré.

---

## Étape 6 — faire taire les constats bruyants

Si un constat ne s'applique pas à ton environnement, exclus-le plutôt que d'ignorer l'avertissement :

```bash
bob --ignore ssh.x11.forwarding.server      # ajoute à ~/.config/bob/ignore.yml
bob --unignore ssh.x11.forwarding.server    # retire
sudo bob --show-ignored                     # voir les constats exclus en gris à côté de la sortie normale
```

Un constat exclu déduit zéro point **et disparaît de la sortie** — c'est
l'objet même de l'option. Passe `--show-ignored` pour lister les constats exclus
en gris à côté de la sortie normale. C'est préférable à `--skip=`, qui retire
l'audit de la section entière plutôt qu'un seul constat.

(Avant la v0.14.1, le score et les compteurs JSON honoraient `--ignore` mais le
constat continuait de s'afficher intégralement ; si tu l'avais constaté, c'est
corrigé.)

---

## Étape 7 — automatiser les audits récurrents

```bash
sudo bob --install-cron
```

L'assistant te fait passer par nom → planification → heure → e-mail facultatif → profil → langue → sondes sortantes. Fichiers créés :

- `/usr/local/bin/bob-{nom}` — script d'enveloppe qui appelle BOB avec le profil, la langue et la posture réseau que tu as choisis. Ces trois-là sont demandés parce qu'un cron s'exécute en root : avant la v0.16.1 le script lisait la config enregistrée de *root*, pas la tienne, si bien que l'audit nocturne d'un opérateur `desktop` était silencieusement noté en `server` — et comme le profil pilote le code de sortie, il décidait aussi si l'e-mail partait
- `/etc/cron.d/bob-{nom}` — entrée cron du système (BusyBox crond : un bloc de `/etc/crontabs/root`)

Le script appelle le `bob` que tu exécutes au moment où tu installes la tâche — `/usr/local/bin/bob` une fois l'option A de l'étape 1 faite, `~/.local/bin/bob` avec l'option B — puisque c'est cette version qui écrit les options du script. Lancé autrement (`python3 -m bob`), il appelle le `bob` que le `PATH` de root trouve ; s'il n'en trouve aucun, il écrit `/usr/local/bin/bob` et l'assistant avertit que ce chemin n'existe pas.

### S'assurer que la notification peut réellement arriver

Après la dernière question, l'assistant te dit qui entendra parler de cette
tâche. Lis-le : trois de ses cinq réponses sont *personne*.

Le script généré notifie **par e-mail et par rien d'autre**, et seulement
quand l'audit sort en non-zéro — un avertissement, une alerte, une erreur ou une
cible manquée ; un audit propre n'envoie rien. Si tu passes l'adresse, l'audit
tourne quand même et écrit quand même son rapport dans ton répertoire de
journaux — mais rien ne te parvient, et jusqu'à la v0.17.0 rien ne le disait. Un
webhook enregistré dans la config de **root** est l'autre sortie, et un audit
programmé le déclenche bien, mais `--offline` supprime le POST.

Si tu as donné une adresse, l'assistant te dit si un binaire `sendmail` existe.
C'est tout ce qu'il peut te dire, et ce n'est pas assez : un Postfix installé
depuis la distribution et jamais configuré satisfait à ce test et ne délivre
pourtant rien. Établis le reste en envoyant :

```bash
bob --test-email                            # un vrai message à ta première adresse enregistrée, par le transport du cron
```

Il emprunte le même chemin de code que la tâche programmée : un succès ici
signifie que le mail de la tâche prendrait la même route. Il sort en non-zéro
quand `sendmail` refuse le message — l'échec autrement invisible, puisque la
façon de l'apprendre serait le mail qui n'arrive jamais.

*Accepté n'est pas délivré.* Une sortie 0 signifie que le MTA a pris le
message ; un relais ou un filtre anti-spam peut encore le jeter. Vérifie la
boîte de réception une fois. Ensuite, souviens-toi qu'un audit propre n'envoie
aucun mail : le silence signifie un hôte propre ou une route cassée, et
`bob --test-email` permet de les distinguer.

**Pas de MTA sur l'hôte ?** Deux options honnêtes :

| | |
|---|---|
| `postfix` | Un serveur de mail complet. Choisis *« Site Internet »* si l'hôte peut émettre directement, ou *« Système satellite »* en nommant le relais de ton fournisseur si le port 25 est bloqué en sortie, comme le font beaucoup de connexions résidentielles et d'hébergeurs. |
| `msmtp` + `msmtp-mta` | Relaie via un compte mail existant (un `~/.msmtprc` avec ton hôte SMTP, l'utilisateur et un mot de passe d'application). Bien plus léger que Postfix, et la bonne réponse pour un portable ou un petit VPS qui ne fait qu'émettre. |

Les noms de paquets varient selon la distribution, et la configuration du
relais aussi — le guide Postfix de [`AUTOMATION_FR.md`](AUTOMATION_FR.md) en est la
version longue, y compris la partie dont la plupart des gens ont réellement
besoin : relayer via un fournisseur parce que le port 25 est bloqué en sortie.

Ou renonce au mail et utilise un webhook, qui n'a besoin de rien de tout cela. Un audit programmé tourne en root : il lit donc le webhook enregistré dans la configuration de **root** (`/root/.config/bob/config.conf`) — alors que `sudo bob --webhook=URL` enregistre l'URL dans *la tienne*, puisque sous `sudo` BOB écrit dans la configuration de l'utilisateur qui l'a lancé. Pour doter une tâche d'un webhook, ajoute `--webhook URL` à la ligne `bob` de son script, comme le montre [`AUTOMATION_FR.md`](AUTOMATION_FR.md).

Pour tes propres exécutions, enregistre un webhook et teste-le :

```bash
sudo bob --webhook=https://hooks.slack.com/services/T00/B00/XXXX   # audite, envoie le résultat, enregistre l'URL
bob --test-webhook                          # envoie un message de test (sans audit) et quitte
```

`--test-webhook` vérifie que l'URL enregistrée et son récepteur répondent, sans lancer d'audit. Le message de test porte l'étiquette `bob_smoke_test` pour que ton récepteur puisse le filtrer.

Voir [`AUTOMATION_FR.md`](AUTOMATION_FR.md) pour la mise en place complète du cron et du webhook.

---

## Étape 8 — suivre les changements dans le temps

Chaque audit enregistre son état comme ligne de base du suivant (`~/.config/bob/last_baseline.json`) et ajoute son score à `~/.config/bob/history.jsonl` :

```bash
sudo bob --diff                             # n'affiche que ce qui a changé depuis le dernier audit
sudo bob --history                          # courbe des 50 derniers scores, tableau des 10 derniers
sudo bob --reset-baseline                   # supprime la ligne de base (l'historique des scores est conservé)
```

`--watch` relance un audit silencieux toutes les N secondes et affiche, à chaque fois, une ligne de score et ce qui a changé depuis l'exécution précédente :

```bash
sudo bob --watch                            # toutes les 60 s
sudo bob --watch=30                         # toutes les 30 s (10 s minimum)
```

`Ctrl+C` quitte.

---

## Étape 9 — formats de sortie pour les outils

BOB peut produire du JSON / CSV / Markdown / HTML pour les chaînes de traitement :

```bash
sudo bob --format=json | jq '.score'        # le score en JSON
sudo bob --format=csv  > audit.csv          # pour un tableur
sudo bob --format=markdown > /tmp/audit.md  # .md lisible (sur stdout)
sudo bob --format=html     > /tmp/audit.html # rapport HTML (sur stdout)
```

Le CSV porte une ligne par constat et, depuis la v0.18.0, sa dernière
colonne est `key` — le même identifiant que prennent `--explain` et
`--ignore`, et celui sur lequel une ligne de base est indexée. Utilise-la plutôt
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
écartées au lieu d'interrompre tout l'audit ; `unverified` liste les clés des
constats qui disent qu'un check n'a pas pu lire toutes ses données, ce qui fait
du score un plafond (`score_is_upper_bound`, `score_low` / `score_high`). Sans
`--target`, le code de sortie reste piloté par les seuls constats : ce sont donc
ces champs qui montrent à une chaîne de traitement que l'audit était
**incomplet**.

---

## Scénarios courants

### « Je veux juste un score sans bruit »

```bash
sudo bob -q                                 # silencieux — le code de sortie donne le verdict
echo $?                                     # 0=OK / 1=WARN / 2=ALERT / 3=erreur / 4=--target manqué ou invérifiable
```

Branche `-q` dans une tâche cron et teste le code de sortie : c'est l'alerte la plus simple possible.

### « Je veux verrouiller un score minimum »

```bash
sudo bob --target=8                         # affiche l'écart ou la réussite dans la synthèse
# code de sortie 4 si le score est sous 8, ou n'est qu'un plafond (une section n'a pas pu être lue en entier)
```

Utile en CI pour faire échouer un build si un système passe sous ta barre.

### « Je veux un audit en français »

```bash
sudo bob --french                           # raccourci pour --lang=fr
sudo bob --lang=fr                          # explicite
```

Toute la sortie (terminal, `--help`, .log, messages de détail JSON, contenus des webhooks, entrées explain) est localisée — 3104 clés × 2 locales — à trois exceptions près, décrites ci-dessous. `--help` a rejoint la liste en v0.15.3 : il rendait de l'anglais sous `--french` depuis la v0.1.0.

Trois choses restent anglaises à dessein, et un diff bilingue de la sortie d'audit en v0.15.4 a confirmé que ce sont les seules : les **commandes shell** des lignes de remédiation (une commande n'est pas de la prose), les **références CIS** portant un code numéroté (décision v0.11.2 — les références « Bonne pratique », sans code, *sont* traduites), et les **38 libellés de services**, comme `Samba (Windows file sharing)` ou `Apache Web Server`, traités comme des noms de produits même quand ils portent des mots anglais. Ces libellés servent aussi de clé aux entrées `service_risk.*` et entrent dans la ligne de base d'audit : les traduire à la source renommerait 114 entrées de locale et ferait apparaître des changements fantômes dans `--diff` au changement de langue.

---

## Lecture suivante

- [`README_TECH_FR.md`](README_TECH_FR.md) — référence complète des commandes, avec chaque option et les codes de sortie
- [`AUTOMATION_FR.md`](AUTOMATION_FR.md) — cron, webhook et notification par e-mail en détail
- [`../SECURITY_FR.md`](../SECURITY_FR.md) — modèle de menace, ce que BOB est / n'est PAS, variables d'environnement à risque
- [`../CHANGELOG_FR.md`](../CHANGELOG_FR.md) — historique des versions avec les points forts de chacune
- `bob --explain list` — chaque constat que BOB sait expliquer, groupé par famille de benchmark CIS (CIS Ubuntu, CIS Docker, Bonne pratique, …) ; consultable dans le sélecteur curses

Si tu rencontres un bug ou veux qu'un constat soit ajouté, ouvre une issue sur [https://github.com/Masbateno/bodyguard-of-bits](https://github.com/Masbateno/bodyguard-of-bits).

---

© 2026 Cédric Clauzel
