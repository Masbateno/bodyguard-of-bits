*[Read in English](RASPBERRY_PI.md)*

# BOB sur Raspberry Pi

Ce guide couvre l'installation et l'utilisation de BOB sur un Raspberry Pi, et ce
que BOB vérifie de spécifique à ce matériel. Il se termine par **ce qui a été
exactement validé sur une vraie carte** — un Pi Zero W — pour distinguer le
comportement mesuré de l'attendu.

> **Portée honnête.** Tout ce qui figure dans la section « Validé sur du matériel
> réel » ci-dessous a été reproduit et corrigé sur **une seule carte : un
> Raspberry Pi Zero W (ARMv6) sous Raspberry Pi OS 13 (trixie)**. D'autres modèles
> — Pi 4/5 (arm64), et les versions de l'OS antérieures à trixie qui provisionnent
> via `userconf.txt` plutôt qu'un seed cloud-init — différeront dans le détail, et
> une matrice Raspberry Pi solide reste à construire avec eux. Là où ce guide
> énonce un chiffre, c'est un chiffre lu par BOB sur cette carte ; là où il
> généralise, il le dit.

---

## Pourquoi un Pi mérite sa propre passe

BOB raisonne sur du logiciel, et jusqu'à la v0.18.1 il raisonnait sur un PC. Un
Raspberry Pi diffère de façons qui ont changé de vrais verdicts :

- Il **démarre depuis une partition FAT** (`/boot/firmware`). FAT ignore la
  notion de propriétaire ou de bits de permission : tout ce qui y est écrit — y
  compris les fichiers de provisionnement créés par le Raspberry Pi Imager — est
  exposé à ce que le montage accorde et à quiconque retire la carte.
- Son **noyau compile AppArmor mais le laisse éteint au démarrage** : un outil
  qui se fie à `aa-status` est trompé.
- Son **swap est du zram** (RAM compressée), pas un disque.
- Il porte **plusieurs saveurs de noyau** (`rpi-v6`, `rpi-v7`, `rpi-v8`) et ne
  peut démarrer que la sienne.
- Les images récentes embarquent **OpenSSH ≥ 9.8**, qui journalise
  l'authentification sous `sshd-session`, pas `sshd`.

Tout cela est pris en charge à partir de la v0.18.1.

---

## Installation

Les prérequis sont les mêmes que partout, via `pipx` :

```bash
sudo apt install pipx && pipx ensurepath
```

Ouvre un nouveau terminal pour que le changement de `PATH` prenne effet, puis :

```bash
pipx install bodyguard-of-bits
```

Active `sudo bob` et la complétion bash une fois (pipx installe dans
`~/.local/bin`, hors du `PATH` de sudo) :

```bash
sudo ~/.local/bin/bob --install-completion
source /etc/bash_completion.d/bob
```

> **Pi Zero / Zero W / 1 (ARMv6).** Ce sont des cartes lentes. Un premier audit
> prend plus que les quelques secondes d'un ordinateur de bureau ; BOB indique sa
> propre durée à la fin, tu n'as pas à deviner. L'installation ne tire que des
> wheels pur-Python — aucun compilateur nécessaire.

### Le virtualenv créé par `pipx`

`pipx` installe BOB dans son **propre virtualenv isolé** — mesuré sur le Pi
Zero W dans `~/.local/share/pipx/venvs/bodyguard-of-bits`, environ **5 Mo**, au-
dessus d'une base pip/setuptools de **~13 Mo** que `pipx` partage entre toutes
les applications qu'il installe (créée une seule fois). Il utilise le **Python
système** de la carte (3.13 sur trixie), donc aucun second interpréteur n'est
téléchargé, et il ne touche à **rien** de ce que gère apt — les dépendances de
BOB ne peuvent entrer en conflit avec les paquets système, et inversement. La
seule chose posée sur ton `PATH` est le lanceur `~/.local/bin/bob` (via
`pipx ensurepath`).

Gérer tout ça, sans compilateur et sans root :

```bash
pipx upgrade bodyguard-of-bits     # sur place, garde le même venv + lanceur
pipx list                          # montre le venv, sa version et son Python
pipx reinstall bodyguard-of-bits   # reconstruit le venv (ex. après un bump du Python de l'OS)
```

`sudo bob` exécute le même code : l'étape `--install-completion` ci-dessus crée
le lien `/usr/local/bin/bob` vers le lanceur du venv pour que root le trouve
(sinon appelle `sudo ~/.local/bin/bob` directement). La désinstallation retire
tout le venv proprement — rien ne reste dans le Python système.

### Désinstallation

```bash
sudo rm -f /usr/local/bin/bob /etc/bash_completion.d/bob
pipx uninstall bodyguard-of-bits          # retire entièrement le venv isolé
```

---

## Premier audit

```bash
sudo bob
```

`sudo` compte davantage sur un Pi qu'ailleurs : lire les fichiers d'identifiants
de la partition de boot et `/etc/shadow` (pour distinguer une empreinte de mot de
passe encore active d'une périmée) demande root. Sans lui, BOB tourne quand même
et dit, pour chaque chose qu'il n'a pu lire, que la réponse **n'a pas été
établie** — il ne rapporte jamais « propre » sur un fichier qu'il n'a pas vu.

Pour ne lancer que les vérifications spécifiques au Pi :

```bash
sudo bob --check=raspberry_pi
```

Pour comprendre un constat, en clair et avec la référence CIS :

```bash
bob --explain raspberry_pi.seed_password
```

---

## Ce que BOB vérifie sur un Pi

### La partition de boot (la section `raspberry_pi`)

BOB lit les fichiers de provisionnement que l'Imager a pu laisser sur
`/boot/firmware` et rapporte **ce qui est mesurablement présent**, jamais une
supposition :

| Constat | Signification | Remédiation proposée par BOB |
|---|---|---|
| `raspberry_pi.seed_password` | Le seed cloud-init (`user-data`) contient encore le mot de passe d'un compte — empreinte ou clair. Sous trixie, BOB dit aussi si l'empreinte est celle utilisée *actuellement*. | `sudo sed -i -E '/^[[:space:]]*(passwd\|hashed_passwd\|plain_text_passwd):/d' /boot/firmware/user-data` |
| `raspberry_pi.seed_wifi_key` | Le seed (`network-config`) contient encore la clé Wi-Fi (PSK). | `sudo sed -i -E '/^[[:space:]]*password:/d' /boot/firmware/network-config` |
| `raspberry_pi.userconf_present` | Images plus anciennes : `userconf.txt` (`user:empreinte`) est encore présent. | `sudo rm /boot/firmware/userconf.txt` |
| `raspberry_pi.legacy_account` | Le compte historique `pi` existe **et peut se connecter** (pas seulement « existe »). | Le renommer ou le verrouiller. |

La remédiation du seed ne retire **que les lignes secrètes** et laisse `meta-data`
intact — volontairement. Voir « Le problème des identifiants sur la partition de
boot » plus bas pour comprendre pourquoi supprimer tout le fichier est une erreur.

Un fichier de provisionnement présent mais **illisible** bloque le feu vert : BOB
le rapporte comme *non établi* plutôt que de le supposer vide.

### Vérifications transverses au comportement différent sur un Pi

Elles ne sont pas dans la section `raspberry_pi`, mais la v0.18.1 leur a appris la
carte :

- **AppArmor compilé dans le noyau mais éteint au démarrage**
  (`mac_policy.apparmor_off_in_kernel`) : BOB lit la réponse du noyau, pas
  `aa-status`, et pointe la remédiation vers la ligne de commande du noyau.
- **Filtrage par chemin inverse par interface** (`hardening.rp_filter_*`) : le
  noyau applique `max(conf/all, conf/<iface>)`, donc BOB rapporte la posture
  effective de l'interface la plus faible et non `conf/all` seul.
- **Swap sur zram** : reconnu comme RAM compressée, pas jugé comme du swap sur
  disque lent, et jamais assorti d'un avertissement d'usure SSD.
- **Saveurs de noyau** : le redémarrage en attente et le nettoyage de paquets
  raisonnent au sein de la saveur du noyau courant, donc une carte ARMv6 ne se
  voit jamais dire de démarrer un noyau arm64.
- **Services activés par socket** : un service inactif mais dont le `.socket` est
  actif est rapporté comme disponible à la demande, pas comme un démon arrêté.
- **Authentification SSH sous `sshd-session`** (OpenSSH ≥ 9.8) : la détection de
  force brute et des connexions réussies lit le bon identifiant de journal.

---

## Le problème des identifiants sur la partition de boot

Sur la carte validée, le lendemain du flash, le seed cloud-init de la partition
FAT contenait des secrets vivants que tout compte local pouvait lire :

- `user-data` contenait l'**empreinte yescrypt** du compte sudo, identique octet
  pour octet à son entrée `/etc/shadow` ;
- `network-config` contenait la **clé Wi-Fi (PSK) de 64 chiffres hexadécimaux** ;
- les deux en mode **0755**, lisibles par tout utilisateur local, parce que le
  montage vfat applique `fmask=0022` — FAT ne peut rien stocker de plus fermé.

**Pourquoi retirer seulement les lignes secrètes et non le fichier.** cloud-init
exécute ses modules par-instance **une fois par instance-id**, qui vit dans
`meta-data`. Si tu retires les lignes `passwd`/`hashed_passwd`/`plain_text_passwd`
de `user-data` et la ligne `password:` de `network-config` mais gardes
`meta-data`, cloud-init voit la même instance au prochain démarrage et saute ces
modules — Wi-Fi, `/etc/shadow`, netplan et le nom d'hôte restent exactement tels
quels. Supprimer les fichiers du seed donne à cloud-init la source `None` — une
*nouvelle* instance — et il ré-exécute tout, ce qui n'est pas voulu sur une carte
déjà configurée.

Le `--fix --apply` de BOB le fait pour toi et ré-audite ensuite, ou tu peux lancer
les commandes `sed` ci-dessus à la main.

---

## Activer AppArmor (noyau du Pi)

Le noyau standard du Pi compile AppArmor mais ne le démarre pas : `aa-status`
sort en erreur et le noyau rapporte `parameters/enabled = N`. Pour l'activer,
ajoute deux paramètres à la ligne de commande du noyau et redémarre :

```bash
# à ajouter à la ligne unique de /boot/firmware/cmdline.txt (ne pas insérer de saut de ligne)
apparmor=1 security=apparmor
sudo reboot
```

> Mesuré sur le Pi Zero W : après ce changement, le noyau a chargé **121 profils,
> 22 en enforce**. Le **premier** démarrage suivant est environ une minute et
> demie plus lent, le temps que les profils soient compilés et mis en cache ;
> tous les suivants ne sont pas plus lents. Là où le bootloader de ta carte range
> la ligne de commande du noyau ailleurs, BOB nomme le paramètre et ne propose
> aucune commande à l'aveugle.

---

## Validé sur du matériel réel — Pi Zero W

**Carte :** Raspberry Pi Zero W (ARMv6) · Raspberry Pi OS 13 (trixie) · OpenSSH
10.0. C'est le premier audit de BOB sur du matériel Raspberry Pi physique ; il a
guidé les dix correctifs livrés en **v0.18.1**. Chacun a été reproduit sur la
carte, corrigé, et le correctif y a été vérifié.

| # | Ce que BOB 0.18.0 disait (faux) | Ce qui était vrai sur la carte | Corrigé en 0.18.1 |
|---|---|---|---|
| 1 | *OK — aucune connexion SSH réussie* | 71 tentatives échouées, 29 connexions acceptées dans le journal | lit `sshd-session` (OpenSSH ≥ 9.8) |
| 2 | *Aucun identifiant de provisionnement sur la partition de boot* | `user-data` contenait l'empreinte yescrypt vivante du compte sudo | lit le seed cloud-init |
| 3 | (clé Wi-Fi non vue) | `network-config` contenait la clé Wi-Fi, mode 0755 | rapporte la clé Wi-Fi du seed |
| 4 | *AppArmor actif, profils illisibles* | AppArmor compilé, **éteint** au démarrage | lit le noyau ; remédiation = cmdline du noyau |
| 5 | *Filtrage par chemin inverse désactivé* | `conf/all=0` mais `wlan0=2` — filtrait | rapporte la valeur effective de l'interface la plus faible |
| 6 | *service activé mais pas en cours* (−1) | `cups.service` inactif, `cups.socket` **actif** | activé par socket = disponible à la demande |
| 7 | *redémarrer sur un noyau plus récent* | proposait le noyau **arm64** à une carte ARMv6 | raisonne dans la saveur du noyau courant |
| 8 | *swappiness trop agressive, mettre vm.swappiness=1* | le swap est du **zram** (RAM compressée) | reconnaît zram, aucun conseil de réglage disque |
| 9 | *service de sécurité activé mais pas en cours* (−1) | `apparmor.service` sauté par une condition non remplie | lit `ConditionResult=no` — pas une faille |
| 10 | `--check=raspberry_pi --fix` lançait aussi `apt install ufw` | le correctif pare-feu est hors du périmètre choisi | `--fix` n'applique que les sections choisies |

La remédiation du seed cloud-init (constats 2/3) a été prouvée sur la carte avant
d'être écrite dans BOB : retirer les seules lignes secrètes et redémarrer a laissé
Wi-Fi, `/etc/shadow`, netplan et le nom d'hôte inchangés. BOB a ensuite exécuté
tout l'aller-retour lui-même — deux avertissements, `--fix --apply --yes`,
ré-audit, feu vert.

**Ce que cela n'établit *pas*.** Une carte, une architecture (ARMv6), une version
d'OS (trixie). Un Pi 4/5 en arm64, ou une image plus ancienne qui utilise encore
`userconf.txt`, peut révéler des différences que cette passe n'a jamais vues. Les
retours de terrain d'autres modèles valent plus que l'émulation — si tu lances BOB
sur l'un d'eux, les résultats aident à construire la matrice.

---

## Voir aussi

- [Tutoriel — pour démarrer](TUTORIAL_FR.md)
- [Référence technique complète](README_TECH_FR.md)
- [Changelog](../CHANGELOG_FR.md) — l'entrée v0.18.1 détaille chaque correctif Pi

---

© 2026 Cédric Clauzel
