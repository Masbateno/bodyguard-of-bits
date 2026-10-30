# BOB — Politique de sécurité

*[Read in English](SECURITY.md)*

## Vérification de la chaîne de publication : incident emSign

> [!NOTE]
> **Vérifié le 23 octobre 2026 : aucune différence entre les paquets publiés
> de BOB et la source étiquetée dans ce dépôt.** Les 105 versions publiées sur
> PyPI (wheels et sdists) et les 104 wheels construits par piwheels ont été
> comparés, fichier par fichier, à leur étiquette git. BOB est publié sans
> aucun jeton PyPI stocké. Deux étapes de la publication de la 0.26.0 ont
> tourné avec des outils qui faisaient encore confiance aux autorités
> concernées ; la 0.26.1 ferme ce point.

Le 20 octobre 2026, un incident de sécurité touchant les autorités de
certification eMudhra / emSign a été rendu public ([fil Python Discourse](https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576)) :
leurs clés privées étaient trivialement faibles, si bien qu'un client TLS qui
leur faisait encore confiance pouvait recevoir un certificat falsifié — pour
pypi.org entre autres. pip avant la 26.2.2, et `pypa/gh-action-pypi-publish`
avant la v1.14.3
([GHSA-5xjx-3w67-w9x9](https://github.com/pypa/gh-action-pypi-publish/security/advisories/GHSA-5xjx-3w67-w9x9)),
leur faisaient encore confiance.

### Ce qui a été vérifié

| Vérification | Résultat |
|---|---|
| **Contenu.** Les 105 versions (0.1.0 à 0.26.0) : wheel et sdist téléchargés depuis PyPI, SHA-256 contrôlé par rapport à l'index de PyPI, chaque fichier comparé à `git archive <étiquette>` | Aucune différence. Seules les métadonnées produites au build (`*.dist-info/`, `*.egg-info/`, `PKG-INFO`, `setup.cfg`) ne sont pas dans git ; on y trouve, dans chaque wheel, le point d'entrée de la commande `bob = bob.__main__:main`, et aucun wheel ne contient de fichier `.pth` ni de module compilé |
| **piwheels.** Les 104 wheels construits pour Raspberry Pi (0.1.0 à 0.25.1), comparés de la même façon | Aucune différence. La 0.26.0 est encore dans la file d'attente de piwheels |
| **Identifiants.** Comment BOB est publié | GitHub Actions, publication de confiance de PyPI (Trusted Publishing, OIDC), `.github/workflows/publish.yml`, environnement `release`. Aucun jeton d'API PyPI n'existe — aucun n'a pu fuiter, aucun à renouveler. Le jeton GitHub du job de build est en lecture seule |
| **Provenance.** Attestations PyPI (PEP 740) | Les 105 versions en portent, avec pour éditeur `Masbateno/bodyguard-of-bits`, workflow `publish.yml`, et pour sujet l'empreinte du fichier |

Ce que chaque vérification établit, et rien de plus : la comparaison montre que
le code publié est la source étiquetée ; les attestations relient chaque
fichier au workflow de publication de ce dépôt — elles disent qui l'a publié,
pas que ce workflow ou ses outils étaient sains.

### Ce que cela ne couvre pas

- **La publication de la 0.26.0 (le 20 octobre 2026, jour de la
  divulgation publique).** Son build a tourné avec pip 26.2.1 pour récupérer ses outils
  (`build`, `setuptools`), et son envoi a utilisé `pypa/gh-action-pypi-publish`
  v1.14.2 — tous deux faisant encore confiance aux autorités concernées ; la
  v1.14.3 est sortie le jour même, quelques heures plus tard. La comparaison a trouvé les
  fichiers publiés identiques à la source étiquetée ; elle ne prouve pas à elle
  seule que l'environnement de build était sain, ni que rien d'autre ne s'est
  produit pendant le build ou l'envoi.
- **La référence est le dépôt lui-même.** Commits et étiquettes sont poussés
  par SSH, qui ne dépend pas des autorités de certification.
- **Votre propre machine** reste à vérifier de votre côté : mettez pip à jour
  en 26.2.2 ou plus (ainsi que uv et certifi) comme l'indique le fil Python, et
  gardez à jour le paquet `ca-certificates` de votre système.

### Ce qui a changé en 0.28.1

Le backend de build est épinglé par empreinte. `python -m build` crée un
environnement isolé et y installe `setuptools` d'après le `requires =
["setuptools>=77"]` de `pyproject.toml` ; jusqu'à la 0.28.0, c'était la version
du jour (84.2.1 pour la 0.28.0, d'après son journal de build), sans empreinte. Le
workflow de publication passe désormais `requirements-build.txt` —
`setuptools==84.2.1` et ses deux SHA-256 — à cet environnement par
`PIP_CONSTRAINT`. Mesuré avec pip 26.2.2 et build 1.6.1 : le fichier épinglé
construit, une empreinte altérée fait échouer le build, et la roue construite
ainsi contient les mêmes 155 fichiers, octet pour octet, que la roue 0.28.0 de
PyPI. Ce qui est épinglé, c'est le backend : un fichier setuptools d'une autre
empreinte est refusé. Cela ne rend pas reproductible tout l'environnement de
build — l'image du runner, son Python et son système sont ceux de GitHub.

Non couvert : les jobs de test (`pip install -e .`, et `pip install .` dans les
conteneurs d'intégration) construisent encore BOB avec un setuptools non
épinglé. Ils ne publient rien.

### Ce qui a changé en 0.27.0

- chaque action utilisée par les workflows est épinglée par commit, sa version
  écrite à côté, et Dependabot en propose les mises à jour ;
- les outils de test, de lint et de build — pytest, beautifulsoup4, ruff, build
  et ce qu'ils entraînent — sont installés par `pip install --require-hashes`
  depuis `requirements-ci.txt`, qui épingle chacun par version et SHA-256 : un
  fichier non listé fait échouer le job au lieu d'être installé ;
- le build refuse toute étiquette autre qu'un `MAJEUR.MINEUR.CORRECTIF` nu égal
  à la version de `pyproject.toml` ;
- l'environnement `release` où s'exécute l'envoi vers PyPI exige l'approbation
  d'un réviseur et n'admet que les étiquettes correspondant à
  `[0-9]*.[0-9]*.[0-9]*` (un réglage du dépôt).

### Ce qui a changé en 0.26.1

Dans le workflow de publication, avant toute installation de dépendance de
build :

- pip est installé depuis un wheel épinglé par son SHA-256 (la méthode du fil
  Python), et non mis à jour par le pip déjà en place — qui le téléchargerait
  par la connexion même qui est en cause ;
- le job échoue si pip est antérieur à 26.2.2, et journalise les versions avec
  lesquelles il a construit ;
- l'action d'envoi est épinglée par commit sur `pypa/gh-action-pypi-publish`
  v1.14.3 (`7245906…`), et non plus sur une branche mobile.

## Versions supportées

Les correctifs de sécurité sont émis pour la dernière ligne de minor release uniquement. Les minor releases antérieures ne sont pas backportées.

| Version        | Supportée          |
|----------------|--------------------|
| 0.28.x         | ✅ courante         |
| 0.27.x         | ❌ fin de vie       |
| 0.26.x         | ❌ fin de vie       |
| 0.25.x         | ❌ fin de vie       |
| 0.24.x         | ❌ fin de vie       |
| 0.23.x         | ❌ fin de vie       |
| 0.22.x         | ❌ fin de vie       |
| 0.21.x         | ❌ fin de vie       |
| 0.20.x         | ❌ fin de vie       |
| 0.19.x         | ❌ fin de vie       |
| 0.18.x         | ❌ fin de vie       |
| 0.17.x         | ❌ fin de vie       |
| 0.16.x         | ❌ fin de vie       |
| 0.15.x         | ❌ fin de vie       |
| 0.14.x         | ❌ fin de vie       |
| 0.13.x         | ❌ fin de vie       |
| 0.12.x         | ❌ fin de vie       |
| 0.8.x – 0.11.x | ❌ fin de vie       |
| 0.7.x          | ❌ fin de vie       |
| 0.6.x          | ❌ fin de vie       |
| ≤ 0.5.x        | ❌ fin de vie       |

Les correctifs sortent en `0.28.x+1`. Un changement cassant incrémente la version mineure (`0.29.0`).

**v0.27.x est en fin de vie le jour où 0.28.0 sort**, selon la politique
« ligne minor la plus récente uniquement » ci-dessus. Aucun correctif de
sécurité ne sera backporté. Les utilisateurs sur v0.27.x doivent
`pipx upgrade bodyguard-of-bits` vers v0.28.x.

La mise à jour change ce que le score **signifie** quand BOB ne peut pas lire
une partie de l'hôte. Jusqu'en v0.16.0, le score était une somme sur les checks
qui avaient tourné, et un check incapable de lire son entrée ne contribuait
rien — masquer `/etc/ssh/sshd_config` faisait donc **monter** le score de 7 à
8, sur un hôte dont BOB voyait moins. Le nombre est désormais rendu comme le
plafond qu'il est (`≤ 8/10`), le niveau de risque qui en dérive se lit comme un
meilleur cas, et une ligne de résumé indique combien de sections n'ont pas pu
être entièrement lues.

**La v0.16.2 ajoute un troisième état.** Le plafond ne vaut que tant que le
domaine du check aveuglé est encore noté ; quand l'aveuglement retire un
domaine *entier* de la moyenne, le dénominateur change et le nombre peut bouger
dans les deux sens — il s'affiche alors `~ 8/10`, à côté de l'intervalle où on
le sait situé (`entre 6 et 8`). Un portail `--target` échoue fermé dans les deux
cas : il consulte le fait que quelque chose n'a pas été lu, pas la direction de
l'erreur. `score` reste un entier en JSON ; `score_is_upper_bound`,
`unverified`, `score_low`, `score_high` et `unscored_domains` sont additifs.
`--diff` ne rapporte plus un constat comme résolu quand sa section n'a pas été
réévaluée, ni un écart de score comme une amélioration ou une dégradation quand
l'exécution a lu moins que la précédente.

**v0.14.x est en fin de vie depuis le 31-08-2026** (jour de la sortie de v0.15.0,
selon la politique « ligne minor la plus récente uniquement » ci-dessus). Aucun
correctif de sécurité ne sera backporté. Les utilisateurs sur v0.14.x doivent
`pipx upgrade bodyguard-of-bits` vers v0.15.x.

La mise à jour comporte des changements **de comportement**, et l'un d'eux a
délibérément entravé la discipline de versionnage. La v0.15.4 a livré des
changements de score sous un numéro de correctif — exception documentée, prise
pour vider un backlog qui les repoussait depuis plusieurs versions — si bien que
le score d'un hôte peut bouger à cette mise à jour sans que l'hôte ait changé :

* l'isolation des conteneurs coûte désormais des points là où elle relève d'un
  choix de l'opérateur : `--privileged` (−3), un `CAP_SYS_ADMIN` isolé (−2),
  seccomp désactivé (−1). Un conteneur lancé sans aucun drapeau reste à zéro ;
* le chemin nftables atteint la parité avec iptables. Cela **retire** surtout
  une fausse déduction : un hôte nftables correctement durci perdait un point
  pour une règle de loopback qu'il possédait, seule l'écriture `iif` étant
  reconnue et pas `iifname` ;
* les données `user-data` cloud-init lisibles par tous (−2) et une unité socket
  orpheline liée à une adresse non-loopback (−1) sont passées d'INFO à WARN.

La v0.15.x énonce aussi davantage, et affirme moins, là où BOB ne peut pas
voir : un check qui n'a pas pu lire son entrée le dit désormais au lieu de
substituer un défaut. Cette direction ne fait jamais que **retirer** des
déductions.

**v0.13.x est en fin de vie depuis le 29-08-2026** (jour de la sortie de v0.14.0,
selon la politique « ligne minor la plus récente uniquement » ci-dessus). Aucun
correctif de sécurité ne sera backporté. Les utilisateurs sur v0.13.x doivent
`pipx upgrade bodyguard-of-bits` vers v0.14.x. La mise à jour comporte deux
changements **de comportement** : les audits sous les profils `desktop` /
`workstation` rapportent moins d'avertissements (leurs overrides de profil
étaient silencieusement inertes auparavant, si bien qu'un hôte ne pouvait
jamais retourner exit 0), et la sortie redirigée vers un fichier ou un pipe ne
contient plus de codes couleur ANSI — posez `FORCE_COLOR=1` pour retrouver le
comportement précédent.

**v0.12.x est en fin de vie depuis le 20-06-2026** (jour de la sortie de v0.13.0, où l'EOL est formellement déclarée, selon la politique « ligne minor la plus récente uniquement » ci-dessus). Aucun correctif de sécurité ne sera backporté en v0.12.x. Les utilisateurs sur v0.12.x doivent `pipx upgrade bodyguard-of-bits` vers v0.13.x pour recevoir les patchs — l'upgrade est entièrement rétro-compatible (v0.13.0 *ajoute* seulement deux checks INFO-only ; aucun champ de sortie ni code de sortie existant ne change). Les lignes v0.8.x – v0.11.x sont également en fin de vie, chacune remplacée par le minor suivant ; v0.13.x est la seule ligne supportée.

**v0.7.x est en fin de vie depuis le 05-06-2026** (jour de la sortie de v0.8.1, où la déclaration EOL est formalisée, miroir du pattern qui avait retiré v0.6.x en v0.7.2). Aucun correctif de sécurité ne sera backporté en v0.7.x. Les utilisateurs sur v0.7.x doivent `pipx upgrade bodyguard-of-bits` vers v0.8.x pour recevoir les patchs sécurité. La ligne v0.8.x est largement rétro-compatible avec v0.7.x via les re-exports `__init__.py` (le flag JSON legacy `--json-v1` a été retiré plus tard en v0.9.0), mais **un BREAKING comportemental** atterrit en v0.8.1 : le profil d'audit `workstation` n'est plus un alias silencieux de `desktop` — c'est un profil first-class business-tier qui conserve `backup.no_backup` / `auditd.*` / `mac_policy.apparmor_no_enforce` à WARN tout en relâchant la même ergonomie SSH / clamav / rootkit / file_integrity / log_rotation / secure_boot que `desktop`. Les utilisateurs de `bob -p workstation` qui veulent la sémantique pre-v0.8.1 peuvent copier `bob/data/profiles/desktop.conf` vers `~/.config/bob/profiles/workstation.conf`.

**v0.6.x est en fin de vie depuis le 01-06-2026** (jour même de la sortie de v0.7.0). Aucun correctif de sécurité ne sera backporté en v0.6.x. Les utilisateurs sur v0.6.x doivent `pipx upgrade bodyguard-of-bits` vers v0.8.x pour recevoir les patchs sécurité. La chaîne d'upgrade v0.7.x → v0.8.x est rétro-compatible avec l'API publique v0.6.x via les re-exports `__init__.py` (le flag JSON legacy `--json-v1` a été retiré plus tard en v0.9.0).

v0.5.x a été déclarée EOL le jour même de la sortie de v0.6.0 (25-05-2026). La release v0.6.0 est rétro-compatible avec l'intégralité de l'API publique v0.5.x via les re-exports `__init__.py` — l'upgrade est un `pipx upgrade bodyguard-of-bits` sans changement de code requis côté utilisateur.

## Signaler une vulnérabilité

**N'ouvrez pas d'issue GitHub publique pour un signalement de sécurité.**

Signalez les problèmes de sécurité par email à :

```
cedricclauzel@mailo.com
```

avec le préfixe d'objet `[BOB security]`. Inclure :

  - Version BOB (`bob --version`)
  - Plateforme (distro + version, version du noyau)
  - Reproduction minimale (commandes, comportement attendu vs observé)
  - Évaluation d'impact telle que vous la voyez

Vous recevrez un acquittement sous **7 jours**. Un correctif ou plan de remédiation sera communiqué sous **30 jours** pour les problèmes haute sévérité (exécution de code arbitraire, escalade de privilèges, fuite de données sensibles). Les problèmes de moindre sévérité (déni de service contre l'audit lui-même, divulgation d'informations sur des valeurs sysctl publiques, etc.) sont traités au mieux sur le tracker d'issues publique une fois acquittés.

C'est un projet maintenu en solo. Merci d'être patient ; une assignation CVE n'est pas garantie pour chaque rapport.

## Modèle de menace

Cette section est la source faisant autorité pour « ce contre quoi BOB défend et ce contre quoi il ne défend pas ». À lire avant d'intégrer BOB à une pipeline de sécurité.

### Ce qu'est BOB

BOB est un outil **en lecture seule (audit-only)**. Il inspecte l'état du système Linux local et reporte les constats vers le terminal, un fichier de log, et optionnellement une sortie JSON ou un webhook sortant. Il est invoqué par un utilisateur privilégié (`sudo bob`) sur un système que l'utilisateur contrôle déjà.

BOB **n'est pas** :

  - un daemon qui écoute sur un port réseau (aucune surface d'attaque entrante) ;
  - un agent distant (aucune connexion command-and-control à distance) ;
  - un outil de défense active (BOB ne bloque pas de trafic, ne tue pas de processus, ne modifie pas de règles pare-feu de lui-même — le mode `--fix` demande confirmation à l'utilisateur pour chaque commande) ;
  - un outil de forensics (pas de chain-of-custody, pas de stockage de preuves immuable) ;
  - un scanner de vulnérabilités (pas de sondage de bases CVE, pas de test d'exploitation, pas de fingerprinting de versions logicielles vs problèmes connus — utilisez OpenVAS, Nessus, Wazuh, etc.) ;
  - un moteur d'analyse de menaces / threat-modeling (pas d'énumération de chemins d'attaque, pas de probing actif de joignabilité depuis l'extérieur de l'hôte, pas de simulation de scénarios de compromission — utilisez des scanners externes ou du red-team tooling) ;
  - un système de verdict autonome. Le score BOB reflète **l'hygiène de configuration sous le profil d'audit actif et le contexte réseau détecté** — pas un verdict de sécurité absolu. Un score propre signifie « hygiéniquement configuré pour le profil choisi dans le contexte détecté », pas « impossible à compromettre ». Une interprétation humaine est requise pour traduire le verdict en risque opérationnel. Voir README_FR.md « Ce que BOB est — et ce qu'il n'est pas » pour la déclaration de périmètre côté utilisateur.

### Modèle d'adversaire

BOB pose trois hypothèses sur son environnement d'exécution :

  1. **L'utilisateur invocant est de confiance.** `sudo bob` tourne en tant que root par conception. Un utilisateur avec accès sudo a déjà le contrôle complet du système ; BOB n'est pas un pare-feu de privilèges contre lui.
  2. **La disposition du système de fichiers local est saine.** BOB lit `/etc/`, `/proc/`, `/var/log/`, `~/.ssh/`, etc. Si ces chemins ont été falsifiés par un attaquant qui a déjà root, les constats de BOB peuvent être trompeurs. BOB fait partie de la chaîne d'outils d'audit post-compromission, pas de détection pré-compromission.
  3. **Le gestionnaire de paquets de l'hôte est intact.** Les checks comme `apt-cache policy`, `fwupdmgr get-updates`, `systemctl is-active` reposent sur des binaires système légitimes. Un gestionnaire de paquets compromis qui ment trompera BOB.

### Frontières de confiance

BOB traverse trois frontières de confiance pendant une exécution :

| Frontière                       | Entrée vers BOB                                                                                            | Défense côté BOB                                                                                                                                                                                                                                                                |
|---------------------------------|------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Config user-contrôlée**       | `~/.config/bob/config.conf`, `services.d/*.json`, `checks.d/*.py`, `profiles/*.conf`                       | Validation JSON Schema stricte (`bob/data/schemas/`), sanitization ANSI (`bob.plugin_checks`), limites de taille de fichier, vérification d'identifiant Python sur `config_key`                                                                                                   |
| **Contenu de fichiers système** | `/etc/ssh/sshd_config`, `/var/log/auth.log`, fichiers cron, sudoers…                                       | Lectures bornées (`errors='replace'`, plafonds de taille, max lignes), les regex ne s'ancrent jamais sur du contenu user, `_C_LOCALE_ENV` pour subprocess afin d'éviter le parsing dépendant de la locale                                                                          |
| **Sortie de subprocess**        | `ufw status`, `ss -tulnp`, `iptables -L`, `journalctl`, `openssl x509` …                                   | Tous les appels subprocess ont `timeout=`, mode capture, aucun `shell=True` nulle part — `--fix` lance chaque commande comme liste d'arguments et refuse celle qui exige un shell — la sortie n'est jamais `eval`uée ni interpolée dans une autre commande                                            |

### Hors périmètre

  - **Compromission root préexistante.** BOB ne peut pas détecter un rootkit qui a remplacé les binaires sur lesquels il s'appuie (`ss`, `iptables`, …). Utilisez un scanner d'intégrité séparé (AIDE, Tripwire — BOB recommande d'installer ceux-ci).
  - **Attaques au niveau noyau.** BOB lit `/proc/sys` et lui fait confiance. Un module noyau malveillant peut mentir sur chaque valeur sysctl.
  - **Vulnérabilités au niveau applicatif.** BOB audite la surface de durcissement OS, pas la sécurité d'applications utilisateur arbitraires.

### Mode `--fix`

Le mode `--fix` affiche les commandes de remédiation et ne les exécute qu'après que l'utilisateur tape `y`. BOB **n'écrit jamais** vers des fichiers système en dehors de `~/.config/bob/` et du répertoire de log choisi par l'utilisateur sans confirmation explicite. Même en mode `--apply` (correction automatique), seules les commandes listées dans le texte de remédiation propre à BOB sont éligibles — il n'y a pas d'eval de messages de constats ni d'expansion shell de données dynamiques.

Depuis la **v0.16.4**, l'ensemble éligible est plus étroit encore, et resserré
là où les commandes sont *classées* et non là où elles sont exécutées. Une
commande n'est exécutée que si elle est déclarée `cmd_type="fix"` — un
diagnostic comme `smartctl -a` est la preuve d'un constat, pas sa remédiation,
et il était exécuté puis annoncé comme appliqué — et seulement si BOB peut la
lancer sans surveillance : aucun opérateur shell, aucun éditeur interactif.
Tout le reste est affiché avec sa commande sans jamais être exécuté, de sorte
que le compteur au-dessus de l'invite de confirmation est une promesse
tenable. Les chemins interpolés dans une commande passent par `shlex.quote`,
et l'exécution se fait par `shlex.split`, sans shell.

### Plugin checks (`~/.config/bob/checks.d/*.py`)

Depuis la **v0.7.0**, les plugins s'exécutent dans un **sandbox in-process restreint** :

  - Isolation de processus via `multiprocessing.get_context("spawn")` (interpréteur
    Python séparé, aucune mémoire partagée avec l'audit).
  - Timeout de 5 secondes en temps réel + `RLIMIT_AS = 256 Mio` + `RLIMIT_CPU = 10 s`
    appliqués dans le worker.
  - Liste blanche d'imports (uniquement `bob.scoring` et un sous-ensemble choisi de
    la stdlib — `json`, `re`, `pathlib`, `datetime`, …).
  - `__builtins__` restreints (ni `eval` / `exec` / `compile` / `__import__` /
    `input` / `breakpoint`), installés sous forme d'une sous-classe de dict
    `_ImmutableBuiltins` qui redéfinit `__setitem__` et consorts pour lever
    TypeError. Cela bloque le chemin de mutation naturel en Python
    `bins["eval"] = ...`. Un attaquant déterminé peut toujours contourner via
    `dict.__setitem__(bins, "eval", ...)` (méthode de base non liée) ; les
    alternatives réellement immuables (`MappingProxyType`, `frozendict`)
    déclenchent une `SystemError` depuis les chemins rapides C des dicts de
    CPython dont `exec()` a besoin — l'approche par sous-classe est donc le
    maximum que Python permet ici.
  - Wrapper `open()` qui refuse les modes écriture ET interdit la lecture d'une
    courte liste de chemins notoirement sensibles (`/etc/shadow`, `~/.ssh/id_*`,
    `/dev/mem`, …).
  - Méthodes d'écriture de `pathlib.Path` monkey-patchées en `PermissionError`.
  - **Durcissement du chargeur** (v0.14.1) : un plugin doit être un *fichier régulier*, et le source est lu par une lecture bornée. Le plafond de 64 Ko était appliqué via `stat().st_size`, qui vaut `0` pour un périphérique caractère — si bien que `ln -s /dev/zero ~/.config/bob/checks.d/p.py` passait le plafond et était lu jusqu'à l'intervention de l'OOM killer.
  - Retrait extensif des attributs dangereux du module `os`
    (subprocess/spawn, E/S sur descripteurs bruts, écritures FS, changements de
    privilèges, mutations d'environnement, …).
  - Le CheckResult transite du worker vers le parent par un aller-retour en dict
    JSON-safe (et non par un pickle de l'objet contrôlé par le plugin), de sorte
    qu'un `__reduce__` malveillant dans `template_vars` ne peut pas déclencher
    d'exécution de code dans le parent.
  - Le parent n'exécute **jamais** (`exec`) le source du plugin — `_load_one` est
    en lecture AST seule (taille + syntaxe + présence de `run_check` + extraction
    de `CHECK_NAME`).

#### Modèle de menace — ce contre quoi le sandbox protège, et ce contre quoi il ne protège PAS

**Un sandbox Python in-process n'est pas une frontière de sécurité** — c'est une
couche de défense en profondeur. La communauté Python converge sur cette position
depuis 2012 (PEP 416, rejetée) : un attaquant déterminé peut toujours atteindre
les builtins non restreints via la chaîne `__globals__["__builtins__"]` de
n'importe quel module stdlib autorisé, et aucune mitigation au niveau Python ne
peut fermer cela sans casser l'usage légitime de ces modules. RestrictedPython
durcit l'accès aux attributs au niveau bytecode mais n'attrape pas la chaîne
`__globals__` (uniquement les lookups d'attributs publics + l'accès dict).

Ce que le sandbox **arrête** :

  - **Les accidents** — un plugin bogué qui appelle `os.unlink`, boucle
    indéfiniment, alloue 2 Gio, fuit des handles.
  - **Les attaques naïves** — `import subprocess; subprocess.run(...)` au niveau
    module, `open("/etc/passwd", "w")`, `eval(...)`.
  - **Les lectures en député confus** — un `open("/etc/shadow")` accidentel parce
    que l'utilisateur a oublié que BOB tourne en root.

Ce qu'il **n'arrête PAS** :

  - Un attaquant déterminé qui connaît le playbook d'évasion Python
    (`json.dumps.__globals__["__builtins__"]["__import__"]` est atteignable par
    n'importe quel plugin — c'est *attendu* et testé dans
    `TestKnownInProcessLimitation::test_real_builtins_reachable_via_stdlib_globals`).
  - Le contournement `dict.__setitem__(bins, "eval", real_eval)` de la sous-classe
    de builtins restreints — également épinglé comme limitation connue dans
    `TestKnownInProcessLimitation::test_i1_known_limitation_unbound_dict_setitem_bypass`.
  - Les attaques par canal auxiliaire via le timing, l'ordonnancement ou les
    ressources partagées.
  - Les attaques exploitant la propre surface de parsing de BOB (un `sshd_config`
    malveillant que BOB tente d'auditer).

**Une isolation réellement adverse exige une frontière au niveau de l'OS.** Le paquet Debian
livre un profil AppArmor (`debian/apparmor.d/bob`) qui confine le processus BOB
lui-même une fois appliqué. Il est en mode complain par défaut (il journalise sans
bloquer) : la frontière contre les plugins malveillants n'existe qu'après `aa-enforce`. Les distributions qui livrent BOB dans un runtime confiné (snap,
flatpak, conteneur) héritent de l'isolation de ce runtime.

Si vous exécutez BOB non confiné sous `sudo`, **vous devez relire le code de vos
plugins avant de les installer**. Le sandbox élève la barre contre les accidents
et les attaques naïves ; il ne remplace pas la confiance.

~~`BOB_SANDBOX_LEGACY=1`~~ (retirée en v0.9.0 TD-1) permettait autrefois de
désactiver entièrement le sandbox et d'exécuter le plugin dans le processus
parent — cela produisait une entrée de log CRITICAL + un WARNING voyant sur
stderr à chaque exécution. La variable d'environnement est désormais ignorée ;
les plugins s'exécutent toujours dans le processus enfant sandboxé.

## Rendu de texte non fiable

Les messages de constats interpolent des valeurs que BOB lit sur le système —
noms de fichiers, d'unités, de processus, commandes cron, noms de paquets,
sujets de certificats. Un attaquant capable de nommer un processus ou d'écrire
une entrée cron sur la machine auditée peut donc placer du texte arbitraire dans
le rapport. Deux défenses distinctes s'appliquent, et elles sont distinctes à
dessein.

**Couche 1 — les caractères de contrôle, à la construction.** Depuis la
**v0.14.1**, les champs `message`, `detail` et `note` de chaque constat sont
débarrassés des séquences ANSI et des caractères de contrôle dans
`Finding.__post_init__()`, le point unique par lequel tous les constats sont
construits. Cette garantie-là atteint toutes les sorties. (`cmd` conserve ses
sauts de ligne — un bloc de remédiation est légitimement multiligne — et perd
tout le reste.)

Ce n'est pas cosmétique. Un script world-writable dans `/etc/cron.daily` dont le
*nom de fichier* portait `\033]0;…\007` voyait la séquence rendue telle quelle
dans le terminal de l'opérateur : elle réécrivait le titre de la fenêtre et
corrompait l'encadré de synthèse. Avec des séquences de déplacement du curseur,
le même vecteur peut écraser des lignes d'audit déjà imprimées — c'est-à-dire
faire mentir le rapport sur *d'autres* constats, ce qui compte davantage dans un
auditeur de sécurité que dans la plupart des outils.

**Couche 2 — le balisage, au rendu, format par format.** La couche 1 retire les
octets de contrôle ; elle ne retire pas le balisage et ne le peut pas, car ce
qui constitue du balisage dépend entièrement de la destination du texte.
Échapper à la construction corromprait le terminal et le JSON, qui ont besoin
des caractères tels quels. Chaque écrivain échappe donc pour son propre format :

| Sortie | Traitement |
|---|---|
| Terminal, JSON | rien au-delà de la couche 1 — aucun des deux n'interprète de balisage |
| HTML | `html.escape(..., quote=True)` sur chaque valeur interpolée |
| Markdown | `<` en entité, `[` et `]` échappés pour que liens et images ne se rendent pas, `\|` pour que le tableau survive ; `cmd` va dans un code span dont la clôture est dimensionnée à son contenu |
| Slack | `&`, `<` et `>` échappés selon les règles propres à Slack |
| CSV | une cellule commençant par `=`, `+`, `-` ou `@` est préfixée d'une apostrophe, pour qu'un contenu ayant seulement *transité* par BOB ne puisse pas s'exécuter à l'ouverture de l'export |
| Rapport HTML par email | `html.escape` plus `_safe_url`, qui ramène les URL `javascript:`, `data:` et `vbscript:` à `#`. Il s'agit de `bob/report_markdown.py`, atteint par `--install-cron` lorsqu'une adresse est fournie — l'audit planifié envoie son rapport en HTML. **Ce n'est pas** le rapport `-d`, que cette ligne désignait jusqu'en v0.16.0 : `-d` écrit un `.log` en texte brut et n'interprète aucun balisage. |

**La v0.15.0 a trouvé cette couche absente chez deux écrivains.** Le rapport
Markdown n'échappait que le séparateur de tableau : `<img src=x onerror=…>`
s'exécutait dans tout rendu laissant passer le HTML, `[click](javascript:…)`
s'affichait comme un lien actif, et `![x](https://…)` faisait télécharger une
image distante par la machine de l'auditeur à l'ouverture. La charge Slack
partait verbatim, où `<!channel>` notifie tout un espace de travail et
`<http://ailleurs|paraît légitime>` s'affiche comme un lien dont le texte
visible est sous le même contrôle que la destination. Les deux sont corrigés,
les deux sont verrouillés par des tests. La leçon à retenir est que le point de
passage unique de la couche 1 a été lu, un temps, comme couvrant plus qu'il ne
couvrait.

## Variables d'environnement

BOB lit les variables d'environnement suivantes. Toutes sont opt-in ; aucune n'est requise pour un fonctionnement normal.

| Variable | Défaut | Effet |
|---|---|---|
| `BOB_SHARE` | non défini | Force le chemin du dossier de données du package (`bob/data/`). Utilisé par les packageurs distro lorsque les données sont livrées hors de l'arbre Python. |
| `BOB_WEBHOOK_ALLOW_INSECURE=1` | non défini | Autorise les URLs `http://` pour les webhooks (rejet par défaut). La charge utile fuite hostname + IP publique + score + alertes en clair — à n'utiliser que sur réseau privé de confiance ou en lab local. |
| ~~`BOB_SANDBOX_LEGACY=1`~~ | retiré en v0.9.0 (TD-1) | Pre-v0.9.0, exécutait les plugins dans le processus parent au lieu du sandbox enfant (spawn). Retiré ; l'env var est ignorée. Les plugins s'exécutent toujours dans le sandbox enfant. |
| `BOB_DEBUG=1` | non défini | Commutateur de diagnostic, deux effets. (1) Affiche la trace Python complète sur sortie `EXIT_ERROR=3` (depuis v0.6.1) — sans, une seule ligne résumé + un hint pour activer la variable s'affichent. (2) Depuis la **v0.13.3**, installe un vrai handler de logging sur le logger `bob` au niveau DEBUG, ce qui rend visibles les enregistrements internes `logger.debug` / `logger.warning` autrement avalés (notamment la trace d'échec par subprocess de `_run()`). Utile pour diagnostiquer les crashs et les checks qui ne renvoient silencieusement rien ; jamais requis en production. |
| `FORCE_COLOR=1` | non définie | Force la couleur ANSI même quand stdout n'est pas un terminal. Ajoutée en v0.14.0, quand la couleur est devenue auto-détectée (`--no-color` → `NO_COLOR` → `FORCE_COLOR` → `isatty()`) et que la sortie redirigée a cessé de porter des codes d'échappement. Documentée dans la note de fin de vie v0.13.x ci-dessus mais absente de cette table jusqu'en v0.16.0. |
| `NO_COLOR` | non défini | Désactive toute sortie couleur ANSI, équivalent à `--no-color`. Suit la convention [no-color.org](https://no-color.org) : **toute valeur non vide** désactive la couleur, une valeur vide est ignorée. Honorée depuis la **v0.13.3**. |

## Surface réseau

Par défaut, BOB effectue **deux** appels HTTPS sortants :

  1. **Lookup d'IP publique** au démarrage de l'audit (providers par défaut : `api.ipify.org`, `icanhazip.com`, `ifconfig.me`). Utilisé pour classifier le contexte réseau (local vs public). Chaque provider a un timeout de 3 secondes.
  2. **Webhook POST** si `--webhook=URL` est donné. POST de payload `application/json` vers l'URL fournie par l'utilisateur.

Les deux peuvent être désactivés avec `--offline` (ou `-o`). En mode `--offline`, BOB effectue **zéro** connexion réseau sortante. C'est le réglage recommandé pour les sandboxes CI / build de distro / environnements air-gapped.

Pas de télémétrie, pas d'analytics, pas de vérification de mise à jour automatique, pas de logging distant : BOB ne phone jamais home.

## Manipulation des données

  - **Rapports** : Les rapports détaillés `-d` sont écrits vers le répertoire de log configuré par l'utilisateur (par défaut : `~/.local/share/bob/logs/`). Les permissions de fichier sont `0600` (propriétaire uniquement ; chownés de retour vers `$SUDO_USER` quand l'invocation passe par sudo, ou `$DOAS_USER` par doas depuis la 0.25.1). Le nom du rapport est entièrement prédictible (`bob_%Y%m%d_%H%M%S.log`) et le fichier est créé en root sous sudo : depuis la **v0.14.1** il est donc ouvert avec `O_NOFOLLOW` et chowné via le descripteur déjà détenu (`os.fchown`) plutôt que par son nom. Sans cela, quiconque peut écrire dans le répertoire cible — cas atteignable dès qu'un opérateur pointe `--output-dir` vers un emplacement partagé — pourrait pré-planter un lien symbolique et faire tronquer par root, puis lui céder la propriété d', un fichier arbitraire.
  - **Les écritures de rapport sont best-effort** (v0.14.1). Le rapport est un artefact secondaire et ne doit jamais entraîner l'audit dans sa chute : à la première erreur d'E/S il se désactive, le signale une fois sur stderr, et l'audit se termine normalement. Avant la v0.14.1, un système de fichiers plein coûtait l'exécution entière — exit 3 et aucun audit.
  - **Config** : `~/.config/bob/config.conf` est `0600` (propriétaire uniquement).
  - **Baseline** : `~/.config/bob/last_baseline.json` est `0600`. Contient uniquement des clés de constats, scores, et listes de ports — pas de secrets, pas de contenus de fichiers, pas de PII autre que le nom d'hôte.
  - **Historique** : `~/.config/bob/history.jsonl` est `0600`. Une ligne par audit : timestamp + score + niveau. Rotation à 1000 entrées.
  - **Toutes les lectures d'état sont bornées** (v0.14.1). Chaque fichier d'état, ainsi que le `--diff=CHEMIN` fourni par l'opérateur, passe par `bob._atomic.read_text_capped()`, qui refuse tout ce qui n'est pas un fichier régulier et borne la lecture. Auparavant, un chemin pointant vers un périphérique caractère (`--diff=/dev/zero`, ou `ignore.yml` lié vers lui) épuisait la mémoire, et un FIFO bloquait le processus **indéfiniment** — un cron qui reste suspendu au lieu d'échouer, et à chaque exécution suivante.

Quand BOB est invoqué via `sudo` (ou `doas`, depuis la 0.25.1), les fichiers dans `~/.config/bob/` sont automatiquement chownés de retour vers `$SUDO_USER` (depuis v0.3.6) ou `$DOAS_USER` afin qu'ils restent lisibles/éditables sans sudo par la suite. Depuis la 0.26.1, rien de ce que BOB y écrit en root ne passe par un lien symbolique vers un endroit hors du répertoire personnel de l'utilisateur — historique, baseline, compteurs de récurrence, configuration, liste d'ignorés, répertoire des journaux et rapport `-d` compris. Toute écriture passe par un descripteur de son répertoire, vérifié d'abord : un répertoire sous le répertoire personnel de l'utilisateur qui s'est résolu hors de lui (un `~/.config/bob`, un `~/.config` ou un répertoire de journaux lien symbolique) est refusé — rien n'y est créé, remplacé, changé de mode ni remis —, et le refus est dit sur stderr à la fin de l'audit ; `--manage-logs` n'y liste, supprime ni déplace aucun rapport. Le nom même du fichier est gardé aussi : l'historique et le rapport sont ouverts avec `O_NOFOLLOW`, les autres fichiers d'état renommés par-dessus leur nom. Toute remise passe par un descripteur ouvert avec `O_NOFOLLOW`, vérifié de même. Un lien qui reste dans le répertoire personnel appartient à l'utilisateur, et une exécution sans `sudo` ni `doas` n'est pas jugée. Avant — toutes les versions de la 0.1.0 à la 0.26.0, mesuré sur dix d'entre elles —, root suivait un tel lien — il écrivait dans sa cible, en changeait le mode, la créait à travers un lien pendant et la remettait à l'utilisateur appelant, créait les fichiers d'état et le rapport de BOB dans un répertoire lié et le passait en 0700 —, si bien qu'un compte tournant sous cet utilisateur, sans root, aurait pu se faire remettre un fichier comme `/etc/shadow` ou `/etc/ld.so.preload` au `sudo bob` suivant, ou rendre `/etc` illisible pour tous les autres comptes.

## Recommandations de défense en profondeur (pour les packageurs)

Si BOB est packagé pour une distro qui supporte le MAC (AppArmor sur Ubuntu/Debian, SELinux sur RHEL/Fedora) :

  - Livrer le profil AppArmor optionnel (`debian/apparmor.d/bob` une fois packagé) en mode `complain` par défaut ; offrir `enforce` en opt-in afin que les utilisateurs aventureux aident à débusquer les faux positifs.
  - Le profil DOIT autoriser la lecture sur `/etc/`, `/proc/`, `/sys/`, `/var/log/`, `~/.config/bob/`, `~/.ssh/`, et l'exécution sur les outils système que BOB invoque (~58 binaires couvrant pare-feu, systemd/journal, framework audit, politique MAC, durcissement noyau, antivirus, scan rootkit, NTP, Secure Boot, gestionnaire de paquets). La **liste canonique et exhaustive** est le profil `debian/apparmor.d/bob` packagé — adapter les chemins selon le layout de la distro. Un échantillon représentatif : `ufw`, `ss`, `iptables`, `ip6tables`, `nft`, `systemctl`, `journalctl`, `openssl`, `smartctl`, `fwupdmgr`, `aa-status`, `sestatus`, `mokutil`, `bootctl`, `sysctl`, `ip`, `swapon`, `timedatectl`, `chronyc`, `rkhunter`, `chkrootkit`, `clamscan`, `freshclam`, `aide`, `auditctl`, `fail2ban-client`, `postconf`, `snap`, `dpkg`, `apt-cache`.
  - Le trafic réseau sortant (HTTPS) doit être autorisé pour le lookup d'IP publique et la livraison webhook, sauf si les déploiements reposent exclusivement sur le mode `--offline`.
  - Recommander l'installation de BOB avec `pipx` (chemin d'installation upstream par défaut) afin qu'il vive dans `~/.local/pipx/venvs/bodyguard-of-bits/` plutôt que dans un environnement Python système partagé.

## Politique de divulgation

  - Divulgation coordonnée préférée.
  - Durée d'embargo : 30 jours de l'acquittement au correctif public, extensible par accord mutuel.
  - Crédit : les rapporteurs sont crédités dans le changelog sauf s'ils demandent l'anonymat.

## Remerciements

Les chercheurs en cryptographie ou sécurité qui ont signalé des vulnérabilités à BOB seront listés ici.

*(aucun pour l'instant — soyez le premier)*

---

© 2026 Cédric Clauzel
