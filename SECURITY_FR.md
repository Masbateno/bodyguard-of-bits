# BOB — Politique de sécurité

*[Read in English](SECURITY.md)*

## Versions supportées

Les correctifs de sécurité sont émis pour la dernière ligne de minor release uniquement. Les minor releases antérieures ne sont pas backportées.

| Version        | Supportée          |
|----------------|--------------------|
| 0.16.x         | ✅ courante         |
| 0.15.x         | ❌ fin de vie       |
| 0.14.x         | ❌ fin de vie       |
| 0.13.x         | ❌ fin de vie       |
| 0.12.x         | ❌ fin de vie       |
| 0.8.x – 0.11.x | ❌ fin de vie       |
| 0.7.x          | ❌ fin de vie       |
| 0.6.x          | ❌ fin de vie       |
| ≤ 0.5.x        | ❌ fin de vie       |

Les correctifs sortent en `0.16.x+1`. Un breaking change bump le minor (`0.17.0`).

**v0.15.x est en fin de vie le jour où v0.16.0 sort**, selon la politique
« ligne minor la plus récente uniquement » ci-dessus. Aucun correctif de
sécurité ne sera backporté. Les utilisateurs sur v0.15.x doivent
`pipx upgrade bodyguard-of-bits` vers v0.16.x.

La mise à jour change ce que le score **signifie** quand BOB ne peut pas lire
une partie de l'hôte. Jusqu'en v0.16.0, le score était une somme sur les checks
qui avaient tourné, et un check incapable de lire son entrée ne contribuait
rien — masquer `/etc/ssh/sshd_config` faisait donc **monter** le score de 7 à
8, sur un hôte dont BOB voyait moins. Le nombre est désormais rendu comme le
plafond qu'il est (`≤ 8/10`), le niveau de risque qui en dérive se lit comme un
meilleur cas, et une ligne de résumé indique combien de sections n'ont pas pu
être entièrement lues. `score` reste un entier en JSON ; deux champs additifs,
`score_is_upper_bound` et `unverified`, disent ce qu'il vaut. `--diff` ne
rapporte plus un constat comme résolu quand sa section n'a pas été réévaluée.

**v0.14.x est en fin de vie depuis le 31-08-2026** (jour du ship de v0.15.0,
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

**v0.13.x est en fin de vie depuis le 29-08-2026** (jour du ship de v0.14.0,
selon la politique « ligne minor la plus récente uniquement » ci-dessus). Aucun
correctif de sécurité ne sera backporté. Les utilisateurs sur v0.13.x doivent
`pipx upgrade bodyguard-of-bits` vers v0.14.x. La mise à jour comporte deux
changements **de comportement** : les audits sous les profils `desktop` /
`workstation` rapportent moins d'avertissements (leurs overrides de profil
étaient silencieusement inertes auparavant, si bien qu'un hôte ne pouvait
jamais retourner exit 0), et la sortie redirigée vers un fichier ou un pipe ne
contient plus de codes couleur ANSI — posez `FORCE_COLOR=1` pour retrouver le
comportement précédent.

**v0.12.x est en fin de vie depuis le 20-06-2026** (jour du ship v0.13.0 où l'EOL est formellement déclarée, selon la politique « ligne minor la plus récente uniquement » ci-dessus). Aucun correctif de sécurité ne sera backporté en v0.12.x. Les utilisateurs sur v0.12.x doivent `pipx upgrade bodyguard-of-bits` vers v0.13.x pour recevoir les patchs — l'upgrade est entièrement rétro-compatible (v0.13.0 *ajoute* seulement deux checks INFO-only ; aucun champ de sortie ni code de sortie existant ne change). Les lignes v0.8.x – v0.11.x sont également en fin de vie, chacune remplacée par le minor suivant ; v0.13.x est la seule ligne supportée.

**v0.7.x est en fin de vie depuis le 05-06-2026** (jour du ship v0.8.1 où la déclaration EOL est formalisée, miroir du pattern qui avait retiré v0.6.x en v0.7.2). Aucun correctif de sécurité ne sera backporté en v0.7.x. Les utilisateurs sur v0.7.x doivent `pipx upgrade bodyguard-of-bits` vers v0.8.x pour recevoir les patchs sécurité. La ligne v0.8.x est largement rétro-compatible avec v0.7.x via les re-exports `__init__.py` (le flag JSON legacy `--json-v1` a été retiré plus tard en v0.9.0), mais **un BREAKING comportemental** atterrit en v0.8.1 : le profil d'audit `workstation` n'est plus un alias silencieux de `desktop` — c'est un profil first-class business-tier qui conserve `backup.no_backup` / `auditd.*` / `mac_policy.apparmor_no_enforce` à WARN tout en relâchant la même ergonomie SSH / clamav / rootkit / file_integrity / log_rotation / secure_boot que `desktop`. Les utilisateurs de `bob -p workstation` qui veulent la sémantique pre-v0.8.1 peuvent copier `bob/data/profiles/desktop.conf` vers `~/.config/bob/profiles/workstation.conf`.

**v0.6.x est en fin de vie depuis le 01-06-2026** (jour même du ship v0.7.0). Aucun correctif de sécurité ne sera backporté en v0.6.x. Les utilisateurs sur v0.6.x doivent `pipx upgrade bodyguard-of-bits` vers v0.8.x pour recevoir les patchs sécurité. La chaîne d'upgrade v0.7.x → v0.8.x est rétro-compatible avec l'API publique v0.6.x via les re-exports `__init__.py` (le flag JSON legacy `--json-v1` a été retiré plus tard en v0.9.0).

v0.5.x a été déclarée EOL le jour même où v0.6.0 a été shippée (25-05-2026). La release v0.6.0 est rétro-compatible avec l'intégralité de l'API publique v0.5.x via les re-exports `__init__.py` — l'upgrade est un `pipx upgrade bodyguard-of-bits` sans changement de code requis côté utilisateur.

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

BOB est un outil **en lecture seule (audit-only)**. Il inspecte l'état du système Linux local et reporte les findings vers le terminal, un fichier de log, et optionnellement une sortie JSON ou un webhook sortant. Il est invoqué par un utilisateur privilégié (`sudo bob`) sur un système que l'utilisateur contrôle déjà.

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
  2. **La disposition du système de fichiers local est saine.** BOB lit `/etc/`, `/proc/`, `/var/log/`, `~/.ssh/`, etc. Si ces chemins ont été falsifiés par un attaquant qui a déjà root, les findings de BOB peuvent être trompeurs. BOB fait partie de la chaîne d'outils d'audit post-compromission, pas de détection pré-compromission.
  3. **Le gestionnaire de paquets de l'hôte est intact.** Les checks comme `apt-cache policy`, `fwupdmgr get-updates`, `systemctl is-active` reposent sur des binaires système légitimes. Un gestionnaire de paquets compromis qui ment trompera BOB.

### Frontières de confiance

BOB traverse trois frontières de confiance pendant une exécution :

| Frontière                       | Entrée vers BOB                                                                                            | Défense côté BOB                                                                                                                                                                                                                                                                |
|---------------------------------|------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Config user-contrôlée**       | `~/.config/bob/config.conf`, `services.d/*.json`, `checks.d/*.py`, `profiles/*.conf`                       | Validation JSON Schema stricte (`bob/data/schemas/`), sanitization ANSI (`bob.plugin_checks`), limites de taille de fichier, vérification d'identifiant Python sur `config_key`                                                                                                   |
| **Contenu de fichiers système** | `/etc/ssh/sshd_config`, `/var/log/auth.log`, fichiers cron, sudoers…                                       | Lectures bornées (`errors='replace'`, plafonds de taille, max lignes), les regex ne s'ancrent jamais sur du contenu user, `_C_LOCALE_ENV` pour subprocess afin d'éviter le parsing dépendant de la locale                                                                          |
| **Sortie de subprocess**        | `ufw status`, `ss -tulnp`, `iptables -L`, `journalctl`, `openssl x509` …                                   | Tous les appels subprocess ont `timeout=`, mode capture (pas de `shell=True` sauf dans `--fix` où les commandes sont explicitement approuvées par l'utilisateur), la sortie n'est jamais `eval`uée ni interpolée dans une autre commande                                            |

### Hors périmètre

  - **Compromission root préexistante.** BOB ne peut pas détecter un rootkit qui a remplacé les binaires sur lesquels il s'appuie (`ss`, `iptables`, …). Utilisez un scanner d'intégrité séparé (AIDE, Tripwire — BOB recommande d'installer ceux-ci).
  - **Attaques au niveau noyau.** BOB lit `/proc/sys` et lui fait confiance. Un module noyau malveillant peut mentir sur chaque valeur sysctl.
  - **Vulnérabilités au niveau applicatif.** BOB audite la surface de durcissement OS, pas la sécurité d'applications utilisateur arbitraires.

### Mode `--fix`

Le mode `--fix` affiche les commandes de remédiation et ne les exécute qu'après que l'utilisateur tape `y`. BOB **n'écrit jamais** vers des fichiers système en dehors de `~/.config/bob/` et du répertoire de log choisi par l'utilisateur sans confirmation explicite. Même en mode `--apply` (auto-fix), seules les commandes listées dans le texte de remédiation propre à BOB sont éligibles — il n'y a pas d'eval de messages de findings ni d'expansion shell de données dynamiques.

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
depuis 2012 (PEP 416, retirée) : un attaquant déterminé peut toujours atteindre
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

**Une isolation réellement adverse exige une frontière au niveau de l'OS.** BOB
livre un profil AppArmor (`packaging/apparmor/bob.profile`) qui confine le
processus BOB lui-même ; c'est *la* véritable frontière contre les plugins
malveillants. Les distributions qui livrent BOB dans un runtime confiné (snap,
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

Les messages de findings interpolent des valeurs que BOB lit sur le système —
noms de fichiers, d'unités, de processus, commandes cron, noms de paquets,
sujets de certificats. Un attaquant capable de nommer un processus ou d'écrire
une entrée cron sur la machine auditée peut donc placer du texte arbitraire dans
le rapport. Deux défenses distinctes s'appliquent, et elles sont distinctes à
dessein.

**Couche 1 — les caractères de contrôle, à la construction.** Depuis la
**v0.14.1**, les champs `message`, `detail` et `note` de chaque finding sont
débarrassés des séquences ANSI et des caractères de contrôle dans
`Finding.__post_init__()`, le point unique par lequel tous les findings sont
construits. Cette garantie-là atteint toutes les sorties. (`cmd` conserve ses
sauts de ligne — un bloc de remédiation est légitimement multiligne — et perd
tout le reste.)

Ce n'est pas cosmétique. Un script world-writable dans `/etc/cron.daily` dont le
*nom de fichier* portait `\033]0;…\007` voyait la séquence rendue telle quelle
dans le terminal de l'opérateur : elle réécrivait le titre de la fenêtre et
corrompait l'encadré de synthèse. Avec des séquences de déplacement du curseur,
le même vecteur peut écraser des lignes d'audit déjà imprimées — c'est-à-dire
faire mentir le rapport sur *d'autres* findings, ce qui compte davantage dans un
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

  - **Rapports** : Les rapports détaillés `-d` sont écrits vers le répertoire de log configuré par l'utilisateur (par défaut : `~/.local/share/bob/logs/`). Les permissions de fichier sont `0600` (propriétaire uniquement ; chownés de retour vers `$SUDO_USER` quand l'invocation passe par sudo). Le nom du rapport est entièrement prédictible (`bob_%Y%m%d_%H%M%S.log`) et le fichier est créé en root sous sudo : depuis la **v0.14.1** il est donc ouvert avec `O_NOFOLLOW` et chowné via le descripteur déjà détenu (`os.fchown`) plutôt que par son nom. Sans cela, quiconque peut écrire dans le répertoire cible — cas atteignable dès qu'un opérateur pointe `--output-dir` vers un emplacement partagé — pourrait pré-planter un lien symbolique et faire tronquer par root, puis lui céder la propriété d', un fichier arbitraire.
  - **Les écritures de rapport sont best-effort** (v0.14.1). Le rapport est un artefact secondaire et ne doit jamais entraîner l'audit dans sa chute : à la première erreur d'E/S il se désactive, le signale une fois sur stderr, et l'audit se termine normalement. Avant la v0.14.1, un système de fichiers plein coûtait l'exécution entière — exit 3 et aucun audit.
  - **Config** : `~/.config/bob/config.conf` est `0600` (propriétaire uniquement).
  - **Baseline** : `~/.config/bob/last_baseline.json` est `0600`. Contient uniquement des clés de findings, scores, et listes de ports — pas de secrets, pas de contenus de fichiers, pas de PII autre que le nom d'hôte.
  - **Historique** : `~/.config/bob/history.jsonl` est `0600`. Une ligne par audit : timestamp + score + niveau. Rotation à 1000 entrées.
  - **Toutes les lectures d'état sont bornées** (v0.14.1). Chaque fichier d'état, ainsi que le `--diff=CHEMIN` fourni par l'opérateur, passe par `bob._atomic.read_text_capped()`, qui refuse tout ce qui n'est pas un fichier régulier et borne la lecture. Auparavant, un chemin pointant vers un périphérique caractère (`--diff=/dev/zero`, ou `ignore.yml` lié vers lui) épuisait la mémoire, et un FIFO bloquait le processus **indéfiniment** — un cron qui reste suspendu au lieu d'échouer, et à chaque exécution suivante.

Quand BOB est invoqué via `sudo`, les fichiers dans `~/.config/bob/` sont automatiquement chownés de retour vers `$SUDO_USER` (depuis v0.3.6) afin qu'ils restent lisibles/éditables sans sudo par la suite.

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
