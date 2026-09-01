*[Read in English](CHANGELOG_FULL.md)* · *[TL;DR](../CHANGELOG_FR.md)*

# BOB — Bodyguard Of Bits — Journal des modifications

Toutes les modifications notables du projet sont documentées ici.

---

## [v0.15.3] — 2026-09-01

**Le backlog laissé par v0.15.2, en commençant par ce que les checks de service lisent au-delà d'un port.**

### `server min protocol` est le nom qu'emploie un smb.conf actuel

Samba a renommé `min protocol` en `server min protocol` et gardé la forme
courte comme synonyme déprécié : une configuration écrite aujourd'hui utilise
donc la longue. BOB ne lisait que la courte.

Une machine ayant explicitement activé SMB1 — le vecteur EternalBlue et
WannaCry, que BOB lui-même lève en ALERTE avec une déduction de deux points —
était donc rapportée comme l'ayant désactivé. La signature de cette campagne une
fois de plus : plus la configuration est à jour, plus la détection la rate.

Mesuré contre `testparm`, le parseur de samba lui-même, sur une installation
réelle. Sept configurations, quatre activant SMB1 et trois non, et les sept
s'accordent désormais avec lui. La famille `client min protocol` reste
délibérément ignorée : elle régit ce que cette machine parle *vers* un serveur,
non ce qu'elle accepte en tant que tel. Tous les autres paramètres lus par le
check ont été soumis à `testparm` dans la même passe et sont reconnus sous le
nom qu'emploie BOB, synonymes de partage compris.

### Le même piège, un répertoire plus loin

v0.15.2 avait établi que `Path.exists()` relève EACCES — il n'avale que ENOENT,
ENOTDIR, EBADF et ELOOP — et qu'une seule levée depuis une collecte non gardée
coûtait l'audit entier. Le garde livré couvrait `bob/checks/` et s'arrêtait là.

`bob/config.py` était en dehors. Un `~/.config/bob` non traversable faisait
lever `UserConfig._load` avant le moindre check : code 3, aucun rapport, aucun
finding, un `[Errno 13] Permission denied` brut sur stderr. BOB tourne en root,
mais root est écrasé sur un home NFS et confiné sous SELinux — c'est donc une
installation d'entreprise ordinaire, pas un cas exotique.

Huit sites du chemin d'audit — dans config, ignore, history et le point
d'entrée — passent désormais par `path_exists`, et le garde couvre ces modules
plutôt qu'un seul paquet. `bob/_atomic.py` est délibérément laissé de côté, et
la raison y est vérifiée plutôt qu'affirmée : `read_text_capped` doit lever
FileNotFoundError pour un fichier absent et PermissionError pour un fichier
illisible, parce que `load_baseline` distingue les deux et que v0.9.2 a livré
deux messages localisés distincts. Les confondre déferait cette version.

Les quatre modules atteints seulement par `--install-completion`,
`--install-cron` et la TUI de journaux sont dispensés avec leur raison
consignée, pour qu'une dispense se lise comme une décision et non comme un
oubli — un test échoue si l'une reste sans motif.

La migration n'était pas mécanique, ce qui est la raison pour laquelle chaque
site a été lu d'abord : chez `_atomic`, la réponse sûre est l'inverse de celle
qu'il fallait aux huit autres.

### Un verdict qui dépendait de l'endroit où l'on se tenait

Les quinze services installés par leur propre installeur plutôt que par un
dépôt de distribution — gitea, authelia, vaultwarden, ollama et les autres —
n'avaient jamais vu leurs chemins déclarés confrontés à une installation
réelle. Deux défauts en sont sortis, dont aucun n'a demandé de conteneur.

**Le champ `binary` du registre était déclaré de deux façons et implémenté
d'une troisième.** `bob/registry.py` parlait de « chemins absolus » ; le schéma
JSON dit « noms de commande nus (résolus via $PATH) ou chemins absolus », et le
registre emploie les deux — `mongod` et `jenkins` sont nus. Le code n'honorait
ni l'un ni l'autre : `Path(x).is_file()` résout un nom nu contre le *répertoire
courant*.

Lancer BOB depuis un répertoire contenant par hasard un fichier nommé `mongod`
rapportait donc MongoDB — service classé critique — comme installé, et toute
l'analyse d'exposition du port 27017 suivait sur une machine qui n'en avait
pas. Lancé d'ailleurs, la même machine ne disait rien. Mesuré dans les deux
sens depuis un répertoire temporaire. Le schéma est désormais le contrat
implémenté, et la docstring dit ce que fait le schéma.

**Deux fichiers de configuration déclarés étaient des répertoires.**
`/etc/openvpn` et `/usr/share/jenkins`. En lire un lève IsADirectoryError, que
l'appelant avale : l'entrée était donc inerte, et le port d'openvpn n'était
jamais lu depuis les configurations serveur qui vivent un niveau plus bas.
`/etc/openvpn/{,server/,client/}*.conf` les lit désormais : une configuration
sur 1195 résout bien 1195, vérifié. Le répertoire jenkins est retiré ; le
fichier à côté était déjà juste.

Ce qui a été vérifié plutôt que supposé : Jenkins livre toujours
`/etc/default/jenkins` avec `HTTP_PORT=8080` — lu depuis le paquet actuel, tiré
directement du dépôt amont — et BOB le résout. Ollama a été confronté à son
installation réelle sur la machine de développement : unité au chemin déclaré,
binaire au chemin déclaré, port 11434 résolu et réellement en écoute.

### stderr était capturé puis jeté

`subprocess.run(capture_output=True)` remplit `proc.stderr` ; `run_result` le
jetait. Le garder ne coûte rien — la donnée était déjà là — et cela tranche un
cas mesuré où stdout et le code de retour ont tous deux l'air ordinaire.

`auditctl -l` signale un sous-système d'audit désactivé sur stderr tout en
sortant en 0 avec un stdout vide. C'est indiscernable d'un système d'audit
joignable ne portant aucune règle, et c'est ainsi que BOB le nommait :
`auditd.rules_unreadable`, « les règles n'ont pas pu être listées ». L'énoncé
honnête est que l'opérateur a coupé l'audit — un réglage, pas une lacune de ce
que BOB a pu voir. Les deux ont désormais des findings distincts, et seul le
second est une lacune.

Les autres refus restent inchangés : leur stdout les trahit déjà. iptables,
nft, aa-status et fail2ban-client impriment tous leur explication sur stderr
*et* laissent une signature sur stdout ou le code de retour que les versions
précédentes lisaient déjà.

stderr reste du texte de sous-processus non fiable. Il est confronté à un
marqueur connu, jamais rendu : un test fait passer un chemin par le canal
stderr et échoue s'il atteint le message, le détail ou la clé d'un finding, et
un autre vérifie que le snapshot conserve un drapeau et non le texte.

### La passe de conception : `config_key` ne décide rien

Le dernier item du backlog était de formaliser ce que `"ask"` et les clés
nommées étaient censées vouloir dire. Mesurer d'abord a transformé la question
en une autre, plus simple.

`config_key` est déclaré de quatre façons et lu une fois :

| | schéma | validateur | docstring | `_resolve_ports` | services |
|---|---|---|---|---|---|
| `auto` | ✓ | ✓ | auto-détecte | lit la config | 16 |
| `ask` | ✓ | ✓ | *demander à l'opérateur et enregistrer* | défaut registre | 11 |
| `fixed` | ✓ | ✓ | ports tels quels | défaut registre | 11 |
| clé nommée | ✓ | ✓ | *lire la config utilisateur* | défaut registre | **0** |

Deux de ces descriptions n'ont jamais eu d'implémentation. Le schéma le savait :
son propre texte annonce qu'« une schema v2 scindera ceci en un objet
`port_resolution` typé » — une v2 qui n'est pas venue.

Or depuis v0.15.2, le lecteur ouvre une configuration dès que
`detection.config_files` en nomme une, quel que soit le nom de la stratégie.
Confronter chaque service à ce qui se passe réellement tient en une ligne :
**33 services lisent leur config parce qu'ils déclarent un chemin, 5 retombent
sur le défaut parce qu'ils n'en déclarent pas, et le nom de la stratégie ne
change rien dans aucun des deux groupes.** Le champ est décoratif, et
`config_key` n'est lu qu'à un seul endroit, dans un `or` que `config_files`
absorbe.

Cela recadre l'item. `"ask"` n'est pas une stratégie en attente
d'implémentation ; c'est le champ entier qui a cessé de sélectionner un
comportement. Il n'y a donc rien à concevoir — seulement quelque chose à cesser
d'affirmer.

Les trois déclarations décrivent désormais ce que fait le code, y compris que
le champ est décoratif et que le retirer serait un changement de contrat du
registre, mis en file plutôt que fait : il ne coûte rien à garder et des
consommateurs lisent services.json. L'invariant est verrouillé par des tests
plutôt que laissé à la prose — chaque forme est vérifiée comme se comportant à
l'identique, et un garde échoue si un second lecteur de `config_key` apparaît,
ce qui le rendrait de nouveau porteur.

Ce dernier garde est tout l'objet de l'exercice. Une description affirmant
qu'« ask interroge l'opérateur » est précisément ce qui a permis à huit
services de porter un chemin de configuration jamais ouvert.

### Un test qui ne mordait pas

Le premier jet des nouveaux tests reconstruisait la logique de détection
localement au lieu de piloter `from_system`. Réinjecter le défaut dans samba.py
ne tuait rien — ils validaient leur propre copie. Réécrits pour écrire un
smb.conf et laisser le vrai parseur le lire, la même mutation en tue trois.

**Tests** 7560 → **7633**.

---

## [v0.15.2] — 2026-08-31

**Un test de résistance des deux versions précédentes, et la classe de défauts qu'elles visaient trouvée encore ouverte à sa racine.**

v0.15.0 et v0.15.1 ont été validées localement face à de vrais états système hostiles plutôt que par des mocks : un
`/etc` délibérément mal configuré monté par bind dans un namespace et audité par les vrais collecteurs, la grammaire
UFW confrontée au parser de `ufw` lui-même, et du texte hostile poussé de bout en bout dans chaque format de sortie.
Tout cela tient. L'intérêt du test était ailleurs.

### `_run` jette le code de retour

L'assistant de sous-processus partagé renvoie la sortie standard d'une commande et jette son code de retour :

    return proc.stdout          # le returncode n'est jamais consulté

Un binaire absent, refusé ou en échec rend donc exactement la même chaîne vide qu'une commande saine qui n'a rien à
dire. Cette ambiguïté est délibérée au niveau de la primitive — un code non nul est souvent une information plutôt
qu'un échec (`dpkg-query -W` sort en non nul pour dire « non installé », `systemctl is-active` pour dire
« inactif ») — et seul l'appelant sait de quoi il s'agit. Ce qui manquait, c'était un moyen pour l'appelant qui s'en
soucie de le savoir.

v0.15.0 et v0.15.1 ont fermé cette classe check par check — `rules_readable`, `status_readable`, `query_failed`,
`kernel_ipv6_readable`, `apparmor_profiles_readable` — sans jamais toucher à la primitive partagée. 26 modules
appellent `_run` ; 7 gardaient le résultat. La classe était fermée sur les feuilles déjà visitées, pas à la racine.

### Cinq verdicts reposaient encore sur l'ambiguïté

Tous atteignables d'un coup, et par une condition ordinaire : `iproute2` n'est pas installé sur les images minimales
ni dans beaucoup de conteneurs, et BOB audite des conteneurs depuis v0.13.0. Sur une machine avec 34 sockets en
écoute, retirer `ss` du `PATH` produisait, sans aucune section dégradée ni le moindre avertissement :

| Surface | Ce que BOB affirmait | Ce que BOB savait |
|---|---|---|
| `ports` | `0 listening port(s) detected on this system` | rien — `ss` n'a jamais tourné |
| `ipv6` | aucun service IPv6 en écoute (`ipv6.ufw_disabled_no_listeners`) | rien |
| `network_context` | `0 connexion TCP établie` | rien |
| `services` | « n'écoute pas activement » pour chaque port du registre | rien |
| encadré de synthèse | un ✔ vert en face de « Listening ports » | rien |

Le même écran affichait simultanément « Firewall driver rules could not be listed » — correct, parce que
`firewall_stack` avait reçu le correctif de v0.15.1. Ce contraste sur un seul écran, c'est à quoi ressemble la
classe quand elle n'est fermée qu'à moitié.

Une sixième instance a été trouvée par balayage plutôt qu'à l'œil : `systemd_timers` annonçait « aucun timer »
quand `systemctl list-timers` échouait. Il distinguait déjà « systemctl absent » de « aucun timer », mais pas
« systemctl présent et en échec ».

### Trois angles de plus, alors que le premier balayage semblait propre

Le balayage des commandes ne cherchait que les affirmations *rassurantes*.
Relire les mêmes données dans l'autre sens, et provoquer deux conditions qu'il
ne créait jamais, a retrouvé la classe sous trois formes de plus.

**La direction alarmante.** `is_unit_active` confond « inactif » et « systemd
n'a jamais été interrogé » dans le même False. Avec systemctl aveuglé, BOB
avertissait qu'un sshd *en marche* était « installé mais ne fonctionne pas » —
`systemctl is-active ssh` répond `active` sur la même machine — et l'encadré de
synthèse affichait un ✔ vert en face de « installed — not running », se
contredisant sur un seul écran. Le nouveau `unit_active_state()` renvoie l'état
rapporté ou None ; `is_unit_active` garde son contrat. `fail2ban` et `auditd`
avaient déjà un repli plus fiable (`fail2ban-client ping`, `auditctl -s`) qui ne
se déclenchait que si systemctl était *absent* ; ils y retombent désormais dès
que systemd ne répond pas.

**Une commande qui réussit sans rien dire d'exploitable.** `run_result`
distingue l'échec du silence, pas le sens du non-sens. Avec `iptables` et `nft`
sortant en 0 sur une sortie incompréhensible, `firewall_drivers.no_issues`
certifiait toujours le pare-feu. Le drapeau de v0.15.1 testait la non-vacuité ;
il teste maintenant l'en-tête de chaîne qu'un `iptables -L` qui marche imprime
toujours — le raisonnement que le commentaire de cette version donnait déjà.
`unit_active_state` n'accepte de même que les états émis par systemd.

**Les fichiers, pas les commandes.** Tout le balayage portait sur les
sous-processus. Les lectures sont gardées elles aussi — 87 `except OSError`
dans les checks — mais le garde rend une valeur par défaut et l'appelant ne
peut pas le savoir. Quatre verdicts reposaient dessus :

| Fichier illisible | Ce que BOB affirmait |
|---|---|
| `/etc/sudoers` | « aucun problème détecté » sur les fichiers sensibles et sudoers |
| `/etc/passwd` | satisfecit sur les comptes, recherche d'UID 0 comprise |
| `/etc/login.defs` | « umask système 022 (sûr) » |
| `/etc/ssh/sshd_config` | « connexion root restreinte à l'authentification par clé » |

Le dernier est le plus tranchant : chaque directive retombe sur la valeur par
défaut compilée d'OpenSSH, donc une config illisible contenant
`PermitRootLogin yes` était rapportée comme restreinte, dans le check *et* avec
un ✔ vert dans l'encadré de synthèse.

Tout `except OSError` n'est pas un défaut — un fichier absent signifie
généralement que la fonction n'est pas configurée, ce qui est un fait. Les
quatre corrigés ici sont ceux où « illisible » et « absent » n'ont pas la même
vérité et produisaient le même verdict.

### Énumérer les chemins plutôt que les deviner

L'angle « fichiers » ci-dessus a été sondé sur six fichiers choisis à la main.
C'est un échantillon, pas un balayage, et il a manqué ce qu'un passage
systématique a trouvé immédiatement : chaque littéral `Path("/etc…")` des
checks — 82 au total, 29 présents sur la machine de test — rendu illisible à
tour de rôle, verdicts comparés à une référence. Sur les seize lisibles à la
référence, douze ne produisent aucune affirmation ; trois si.

**`configparser` saute en silence ce qu'il ne peut pas ouvrir.**
`RawConfigParser.read` prend une liste de fichiers candidats et ne renvoie que
ceux qu'il a su lire — un fichier illisible n'est pas une erreur. samba.py avait
déjà un drapeau `conf_readable` et un check qui sortait tôt dessus, mais le
garde était inerte : aucune `OSError` n'atteignait jamais le `except`, donc un
smb.conf illisible devenait une config vide, chaque réglage retombait sur son
défaut, et la machine s'entendait dire que SMB1 était désactivé et les mots de
passe nuls refusés par un parseur qui n'avait rien lu. Les deux sites d'appel —
samba.py et profiles.py — lèvent désormais quand `read` revient vide. Dans
profiles.py, le même piège transformait un profil illisible en profil vide
nommé d'après son fichier, rendant silencieusement à l'opérateur les défauts
qu'il demandait à surcharger ; `load_profile` retombe déjà avec un
avertissement journalisé, donc la levée transforme une mauvaise réponse
silencieuse en réponse visible.

**Les fichiers cron.** `_read_cron_file` avalait son erreur de lecture : une
ligne pipe-to-shell dans un fichier que BOB ne pouvait pas ouvrir était
invisible et le check répondait quand même `cron.ok`. Il rapporte maintenant
les fichiers jamais ouverts — sur la machine de développement elle-même,
lancée sans sudo, ce sont trois entrées `/etc/cron.d` réelles qui étaient
certifiées propres.

**Le stockage journald.** Un `journald.conf` illisible laisse `Storage=` lu
comme chaîne vide, ce qui est aussi l'aspect de « non défini » — et non défini
signifie le défaut `auto` de journald, rapporté persistant si `/var/log/journal`
existe. Une config posant `Storage=volatile`, dont les journaux sont perdus au
redémarrage, était donc rapportée persistante. Une valeur déjà lue reste
digne de confiance ; seul le défaut inféré est retenu.

### Les répertoires, et le piège `exists()` en dessous

Énumérer les *fichiers* lus par les checks laissait de côté les *répertoires*
qu'ils parcourent — `sudoers.d`, `cron.d`, `profile.d`, `logrotate.d` et treize
autres. Rendus non listables à tour de rôle, l'un produit une affirmation
fausse et l'autre quelque chose de pire.

**Un `/etc/logrotate.d`** qui ne se liste pas compte zéro règle, exactement
comme un répertoire vide, et le check répondait « aucune règle logrotate
configurée » — une affirmation sur un répertoire jamais lu.

**Un `/etc/ssh` en mode 0700 faisait perdre l'audit entier.** Aucun rapport,
aucun finding, code 3, une ligne sur stderr. `Path.exists()` a l'air total mais
ne l'est pas : il avale ENOENT, ENOTDIR, EBADF et ELOOP et relève tout le
reste, donc un fichier sous un répertoire que l'auditeur ne peut pas traverser
lève `PermissionError` au lieu de renvoyer False. L'auto-détection du port d'un
service demandait si `sshd_config` existait, depuis le cœur toujours-actif
délibérément non gardé (le garder laisserait du code aval lire des noms jamais
liés), et l'exception emportait le run. Présent bien avant ce cycle — reproduit
à l'identique sur le tag v0.15.1.

Le projet connaissait déjà le mécanisme : `ddns._config_present` porte une
docstring décrivant exactement ce piège, écrite pour un script DuckDNS sous un
`/root` durci. La connaissance était restée locale au seul module qui s'était
fait mordre. `path_exists()` la généralise, les 30 sites d'appel des checks y
passent, et un test interdit tout retour à un `.exists()` nu — un seul suffit à
perdre un run.

La sonde de config ssh a été réécrite au passage. Demander `exists()` d'abord
ne sait pas séparer les trois cas qui comptent, et traiter EACCES comme
« absent » aurait réintroduit toute la classe : une config absente signifie que
sshd tourne réellement sur ses défauts compilés, donc les lire est juste, alors
qu'une config illisible signifie que ces défauts ne décrivent rien de cette
machine. Sonder l'ouverture distingue absent, interdit et lisible.

### Le même principe, côté écriture

Tout ce qui précède concerne la lecture. BOB écrit aussi, et l'une de ces
écritures pouvait détruire le travail qu'elle était censée consigner.

`bob -d` contre un répertoire de logs en lecture seule ou plein affichait
`Fatal error: [Errno 30] Read-only file system` puis s'arrêtait. Aucun finding,
aucun rapport, rien — parce que le fichier de rapport est ouvert avant que le
moindre check ne tourne, et que l'`OSError` remontait jusqu'au gestionnaire
fatal.

Ce qui en fait un défaut plutôt qu'un choix, c'est que le même module répond
déjà correctement une étape plus loin : quand une écriture échoue *après* une
ouverture réussie, `AuditReport` affiche « Report writing disabled (…): No
space left on device », se désactive, et laisse l'audit aller au bout — 129
findings tout de même rendus. La dégradation existait ; elle ne couvrait
simplement pas l'ouverture. Une défaillance une étape plus tôt recevait donc
une réponse strictement pire que la même défaillance une étape plus tard. Les
findings ne dépendent pas du fichier : un rapport impossible à ouvrir dégrade
désormais vers le rapport nul, avec un avertissement nommant le répertoire et
la raison.

Présent sur le tag v0.15.1, comme le piège `exists()`.

### Les fichiers d'état que BOB relit

Cinq fichiers sont écrits par BOB puis relus au run suivant — `config.conf`,
`history.jsonl`, `ignore.yml`, `recurrence.json` et la baseline de comparaison
— et tous les cinq sont des fichiers ordinaires qu'un opérateur ou une écriture
interrompue peut corrompre. Chacun a reçu du binaire, un document tronqué, une
forme JSON fausse, trois mille niveaux d'imbrication et une ligne unique d'un
demi-mégaoctet : vingt combinaisons, dont dix-neuf dégradent proprement, audit
complet, aucune trace.

`config.conf` contenant des octets non-UTF-8 était la vingtième. Il
interrompait tout sur `Fatal error: 'utf-8' codec can't decode byte 0xfa in
position 0` — aucun audit, aucun finding, et sans même nommer le fichier
fautif. `UserConfig._load` documente pourtant qu'il « ignore silencieusement
les fichiers absents et les lignes malformées », et un fichier qui n'est pas de
l'UTF-8 valide est le cas extrême d'une ligne malformée ; c'était simplement le
seul type de dégât que le garde manquait, parce que `UnicodeDecodeError` est un
`ValueError` et que la clause nommait `OSError`. Une config corrompue est
désormais traitée comme une config absente, et les réglages à moitié lus avant
l'octet fautif sont jetés plutôt que conservés. `EmailStore` portait la même
lacune, atteinte seulement par `--email`, et est corrigé avec lui.

Les fichiers de plugin sous `services.d/` ont été vérifiés dans la même passe
et dégradent déjà d'eux-mêmes.

### La couche scoring, balayée et figée

Le nombre que lit l'opérateur est le dernier endroit où une affirmation peut
dépasser ses preuves. Elle a été vérifiée comme un jeu de propriétés sur des
ensembles de findings générés plutôt que sur des exemples choisis — la leçon
de l'échantillonnage vaut aussi pour l'arithmétique — et elle tient.

Le breakdown rend exactement compte du score brut, cap compris : `finalize`
ajoute le cap comme déduction synthétique précisément pour que les raisons
listées restent un compte complet. Le score affiché tient la promesse v0.12.0
selon laquelle 10/10 est réservé à un audit sans rien à corriger, et ne
dégrade jamais un audit sans déduction. Faire taire une clé par `--ignore`
retire son finding **et** sa déduction, restitue exactement ses points et ne
perturbe aucune autre clé — le mode de défaillance aurait été un opérateur
masquant un finding tout en continuant à le payer. Les surcharges de profil
honorent leur contrat dans les deux sens : `info` et `skip` retirent la
déduction avec le finding, `alert` la conserve.

Quatre mille scénarios générés par propriété, couvrant toute la plage 0–10,
caps et clamps à zéro bien représentés. Rien n'a été corrigé ici parce que
rien n'était cassé ; les invariants sont désormais des tests, donc un refactor
futur ne peut plus casser silencieusement l'arithmétique derrière le chiffre
affiché. Les générateurs portent leur propre contrôle de mordant — un test
échoue si les scénarios cessent de couvrir caps, clamps et plage de score, pour
qu'ils ne dégénèrent pas en assertions sur rien.

Une nuance d'étiquetage a été trouvée et délibérément laissée. Le champ
`deductions` d'un domaine inclut le delta du cap : un domaine pare-feu plafonné
à 3/10 rapporte donc « −7 pt » là où 6 points viennent d'une déduction et 1 du
plafond. Le score est juste, le cap est annoncé deux lignes plus haut sur le
même écran, et renommer le champ casserait le schéma JSON v3 pour les
consommateurs : gain faible contre risque non nul.

### Deux copies d'une même règle, encore

Rejouer les angles antérieurs de la campagne ne ferait, pour l'essentiel, que
reconfirmer leurs propres correctifs — v0.15.1 le disait et avait raison, et
toutes les trouvailles depuis viennent d'angles jamais utilisés. Mais un
*motif* a produit les plus gros défauts de ce cycle : une classe fermée sur les
feuilles visitées plutôt qu'à sa racine. Cela vaut d'être interrogé
directement, et c'est détectable mécaniquement — chercher une règle qui vit en
plusieurs copies privées.

Trois noms d'assistants sont dupliqués entre modules de check. L'un comptait.
`_split_addr_port` existe dans `ports` et dans `network_context`, même nom,
comportement différent : `ports` a appris les crochets IPv6 et `%scope` en
v0.15.0, `network_context` gardait un `rfind(":")` qui laissait les crochets
collés à l'adresse. Toute adresse IPv6 échouait donc à
`_is_private_or_loopback` — `[::1]` compris — et une connexion PostgreSQL
locale ordinaire en IPv6 loopback était rapportée comme

> une connexion établie vers une IP externe sur un port sensible

avec une déduction de deux points, le message nommant `[::1]` comme adresse
externe. `[fc00::1]` (ULA) et `[fe80::1]` (link-local) passaient aussi pour
externes.

C'est la grammaire de règles UFW de v0.15.1 qui se répète, une version plus
tard et un module plus loin : deux copies d'une règle, l'une corrigée.
`split_ss_address()` est désormais la grammaire unique, les deux appelants y
délèguent, et un garde échoue si un module qui exécute `ss` redécoupe la
colonne d'adresse lui-même. Le garde a été testé par mutation avec le cache de
bytecode vidé — réinjecter l'ancien `rfind(":")` tue cinq tests, dont le garde
structurel.

Le garde vise les lecteurs de `ss` plutôt que toute regex IPv6 à crochets de
l'arbre, ce qui signalait un voisin honnête : `docker.py` parse des mappings de
ports `[::]:8080->80/tcp`, un format différent qui a légitimement sa propre
grammaire.

### Vingt services qu'aucune machine n'a installés

Seuls 8 des 38 services du registre existent sur la machine de développement :
les lecteurs de configuration des 30 autres n'avaient jamais tourné. Il n'est
pas nécessaire de les installer : `_auto_detect_port` lit des *fichiers*, donc
une copie de `/etc` montée en namespace exerce tout le chemin — ce qui répond
aussi à « installe-les et regarde », puisque 23 démons réseau sur un poste de
travail ouvrent de vrais ports et dégradent la posture de la machine qu'un
outil de durcissement est censé protéger.

Les trois premiers sondés ont produit deux défauts, de forme familière. Le
lecteur prenait les premiers chiffres suivant un mot-clé, or l'argument d'une
directive est très souvent une adresse :

| Directive nginx | Port audité par BOB |
|---|---|
| `listen 8080;` | 8080 |
| `listen 127.0.0.1:8080;` | **127** |
| `listen 192.168.1.10:8443 ssl;` | **192** |
| `listen [::]:443 ssl;` | **aucun** — repli silencieux sur le défaut du registre |

`listen <adresse>:<port>` est la forme de production ordinaire. C'est le défaut
UFW de v0.15.0 — `80/tcp ALLOW IN 192.168.1.22` couvrant les ports 1, 22, 168 et
192 — dans un troisième module, après la colonne d'adresse `ss` plus tôt dans
cette version. Une adresse lue là où on attendait un port, trois fois dans un
seul cycle.

Redis a fourni l'autre moitié du motif : `port 0` signifie « ne pas écouter en
TCP du tout », un réglage *durci*, et BOB annonçait `0/tcp` — un socket qui ne
peut pas exister. Plus l'opérateur est soigneux, plus la lecture est fausse :
la signature même sur laquelle v0.15.0 s'était ouverte.

Le balayage des services restants a ensuite révélé six formats que le lecteur
ignorait : le `http.port` pointé d'Elasticsearch, le `-p 11212` de memcached, le
`listener` de mosquitto, l'élément XML `<PublicPort>` de Jellyfin, l'adresse de
site sans mot-clé de Caddy, et le style `<NOM>_PORT` des fichiers
d'environnement de Jenkins, Vaultwarden et Home Assistant. Quatre se réduisent
à une règle — `(?:[\w.]+[._])?port` — dont le séparateur obligatoire empêche
`passport` de matcher ; XML et Caddyfile ont chacun une branche.

Une régression a été introduite et rattrapée par le balayage lui-même. Capturer
l'argument entier plutôt que des chiffres nus faisait matcher `listen=YES` en
tête de `vsftpd.conf`, et le lecteur abandonnait le fichier au lieu de
poursuivre jusqu'à `listen_port=2121` trois lignes plus bas. Il parcourt
désormais toutes les correspondances et garde la première qui est vraiment un
port.

Vingt services couvrant sept familles de format sont désormais lus
correctement, chacun figé par un test portant sa forme de configuration amont.

### Sept services sans configuration déclarée, et les formes que cachent les autres

La moitié « détection de présence seule » du registre a suivi. Trois des sept
portent bel et bien un port dans un fichier système standard tout en étant
déclarés ``config_key: "fixed"`` : BOB affirmait donc le défaut du registre sans
jamais regarder — PostgreSQL sur 5432 et WireGuard sur 51820 quoi qu'ait réglé
l'opérateur, tous deux en risque critique ou élevé. Chacun demandait ce qui
manquait au lecteur : un joker, PostgreSQL versionnant son répertoire et
WireGuard gardant un fichier par interface ; le ``ListenPort`` en CamelCase, que
la règle pointée ne peut atteindre faute de séparateur ; et le XML de Syncthing,
qui range le port derrière un ``<address>`` plutôt qu'un élément ``*Port*``.

Le balayage des vingt services déjà couverts pour des formes moins évidentes en
a sorti deux autres, opposées l'une à l'autre. `[client]`, dans un fichier
MySQL/MariaDB, porte le port auquel les clients *se connectent*, jamais celui
d'écoute, et il est écrit au-dessus de `[mysqld]` dans les fichiers livrés : un
lecteur qui prend la première correspondance répondait donc avec lui. Et une clé
`port` répétée était lue à sa première occurrence alors que redis, mysql et les
lecteurs YAML appliquent tous la *dernière* : changer un port en ajoutant une
ligne est l'habitude d'opérateur qui a motivé les trouvailles umask et
login.defs de v0.15.0, et elle était lue comme aucun changement.

Les deux découlent d'une distinction unique plutôt que d'une connaissance par
service. `listen` et `listener` sont *additifs* — un serveur peut en déclarer
plusieurs, tous s'appliquent, donc le premier vaut les autres. Une clé `port`
*surcharge*, donc la dernière gagne. nginx répond toujours 80 pour une
configuration qui écoute aussi sur 443 ; redis répond désormais 6380 pour un
fichier dont la seconde ligne l'a relevé.

Cinq autres écarts apparents de ce balayage se sont révélés être des sondes mal
écrites : des configurations nginx compressées sur une seule ligne, où aucun
espace ne précède le mot-clé. Les vraies sont indentées, et le test refait a
montré que le lecteur avait raison — cinquième erreur de banc de ce cycle, et la
raison pour laquelle chacune est désormais vérifiée avant d'être rapportée.

### La configuration que BOB déclarait sans jamais l'ouvrir

Bien parser un fichier ne sert à rien si l'audit n'appelle jamais le parseur.

`_resolve_ports` n'agissait que sur `config_key == "auto"`. Huit services
portent un chemin de configuration sous `config_key: "ask"` — une stratégie que
le registre documente comme « demander à l'opérateur et enregistrer », qu'aucun
code de l'arbre n'implémente — leur fichier était donc déclaré et jamais
ouvert. nginx, apache, caddy, authelia, vaultwarden, homeassistant,
adguard_home et ollama étaient tous audités sur le défaut du registre : un
nginx écoutant sur 8443 était vérifié comme 80 et 443, les règles UFW étaient
cherchées pour deux ports qu'il n'utilise pas, et le port réellement exposé
n'était jamais examiné. Le lecteur savait parfaitement parser ces fichiers — le
balayage précédent l'avait prouvé en appelant le parseur directement, ce qui est
précisément la raison pour laquelle le câblage manquant est resté invisible.

Le dispatch lit désormais dès qu'un chemin de configuration est déclaré, quel
que soit le nom de la stratégie. Deux des onze services `ask` ne déclarent aucun
fichier et gardent le défaut du registre, ce qui est correct pour eux.

Ce câblage exigeait que le lecteur réponde avec **tous** les ports, non un seul.
`listen` est additif : un nginx servant 80 et 443 déclare les deux, et rendre le
premier aurait fait sortir 443 de l'audit — échanger un mauvais port contre un
port manquant. Les clés `port` surchargeantes rendent toujours une seule valeur,
la dernière.

Quatre formes de plus ont été trouvées dans la même passe. `;` ouvre un
commentaire dans la famille INI et seul `#` était retiré : un `; port=9999`
commenté dans un xrdp.ini ou un app.ini de gitea était donc lu comme le port
vivant — la règle UFW commentée et le `NOPASSWD: ALL # temporary` de v0.15.0,
polarité inversée, BOB auditant un port que l'opérateur avait coupé. Le retrait
est ancré en début de ligne, car en nginx `;` termine une instruction et
`listen 8080;` doit survivre. Un port JSON écrit comme chaîne, un port XML porté
par un attribut plutôt qu'un élément, et une valeur YAML derrière un tag `!!int`
explicite étaient tous invisibles ; les trois se lisent désormais.

### `nginx.conf` ne porte aucun `listen` sur une installation standard

Les services encore en `config_key: "fixed"` se sont révélés déjà couverts :
neuf des onze déclarent un fichier de configuration, que le correctif précédent
lit désormais quelle que soit la stratégie, et les deux qui n'en déclarent aucun
— avahi et plex — ont un port réellement non configurable.

La lacune était dans les *chemins*. Mesurée sur les deux dispositions plutôt que
tirée de mémoire : l'image nginx amont range ses blocs serveur dans
`/etc/nginx/conf.d/*.conf`, et le paquet Debian dans `/etc/nginx/sites-enabled/*`
— `nginx.conf` lui-même ne déclarant aucun `listen` dans le premier cas et
seulement des lignes commentées dans le second. Le registre ne déclarait que
`nginx.conf` : le fichier qui décide du port d'écoute n'était donc jamais parmi
ceux que BOB ouvrait.

Les entrées de `sites-enabled` sont des liens symboliques vers
`sites-available` : activer un site *est* le lien. `_is_safe_config_path` refuse
tout lien, ce qui est juste pour `/etc/cron.d` et `/etc/sudoers.d` où tout lien
est suspect, et faux ici — nginx suit le lien, et un auditeur qui lit ce que
nginx lit doit le suivre aussi. Une politique bornée le suit désormais tant que
sa cible reste dans le même répertoire de configuration du service :
`sites-enabled/evil -> /etc/shadow` est toujours refusé et la frontière de
confiance de SECURITY.md tient — rien hors du répertoire propre au service ne
peut être attiré dans un rapport par un lien planté.

Vérifié contre un vrai `nginx-light` Debian : avec `sites-available/default`
passé à `listen 8443`, BOB résout `8443/tcp` et `80/tcp` — le second venant de
la ligne IPv6 laissée intacte — là où il répondait 80 et 443 sans rien ouvrir.

### Cinq distributions annoncées, les chemins d'une seule

Les chemins corrigés jusqu'ici étaient tous ceux de Debian. BOB est éprouvé sur
cinq distributions : cela valait donc d'être mesuré plutôt que supposé, et la
mesure a été prise dans des conteneurs Fedora avec les vrais paquets installés.

`/etc/apache2` n'y existe pas — httpd garde son `Listen` dans
`/etc/httpd/conf/httpd.conf`. `/etc/mysql` n'existe pas — MariaDB utilise
`/etc/my.cnf` et `/etc/my.cnf.d/*.cnf`. `/etc/memcached.conf` n'existe pas — le
port vit dans `/etc/sysconfig/memcached` sous la forme `PORT="11211"`. Et
`/etc/vsftpd.conf` est `/etc/vsftpd/vsftpd.conf`. Chacun de ces services
retombait donc sur le défaut du registre sur toute la famille RHEL : le même
silence qu'une configuration jamais ouverte, à l'échelle d'une distribution.

Les deux familles sont désormais déclarées, Debian d'abord puisqu'elle est la
référence du projet. Vérifié de bout en bout sur des installations réelles de
chacune : sur Fedora avec `Listen 8081`, `PORT="11212"`, `listen_port=2121` et
un fichier d'appoint `my.cnf.d` sur 3307, BOB lit les quatre ; sur Debian les
mêmes quatre se lisent toujours, apache rendant 8081 et 443 puisque
`ports.conf` déclare les deux.

Cinq services sur deux familles. Trente-trois déclarent un chemin de
configuration, et les autres n'ont été confrontés qu'à Debian — l'angle est
ouvert, pas clos.

### Tous les services lus comme absents sur quatre distributions sur cinq

Le travail sur les chemins inter-distributions a soulevé une question que les
chemins eux-mêmes ne pouvaient pas résoudre : comment BOB décide-t-il qu'un
service est installé ? Par `dpkg-query`, et rien d'autre.

`dpkg-query` n'existe ni sur la famille RHEL, ni sur Arch, ni sur openSUSE, ni
sur Alpine. `_run` renvoie une chaîne vide pour un binaire absent, donc la
vérification répondait False ; le repli snap ne trouvait rien ; et la plupart
des services ne déclarent aucun chemin de binaire. Tous les services du
registre étaient donc lus comme NON INSTALLÉS sur quatre des cinq distributions
que BOB revendique — sans erreur ni plantage. L'audit tournait, affichait sa
section services, et rapportait chaque entrée absente.

Mesuré, non déduit : un conteneur Fedora avec httpd, vsftpd, memcached et
mariadb-server installés et confirmés par `rpm -q` — BOB n'en voyait aucun.

La requête parcourt désormais les gestionnaires présents : `dpkg-query -W`,
`rpm -q`, `pacman -Q`, `apk info -e`, chacun une interface de script plutôt
qu'un affichage, chacun sauté si son outil est absent — le coût sur une machine
donnée est donc d'un `_command_exists` par famille. Les noms de paquets
diffèrent aussi — `apache2` chez Debian devient `httpd` chez Fedora et `apache`
chez Arch — les listes du registre ont donc reçu leurs équivalents.

Quatre checks posaient cette question avec un appel dpkg privé chacun :
services, firmware, ddns et updates. `package_installed()` est la réponse
unique, et un garde échoue si un module réinterroge dpkg directement — il a
trouvé le quatrième appelant pendant qu'on l'écrivait. C'est la troisième règle
unifiée dans cette version après la grammaire UFW et la colonne d'adresse `ss`,
et la raison est la même à chaque fois : une règle gardée en plusieurs copies
est une règle qui finira par se contredire.

Vérifié de bout en bout sur des installations réelles : Debian via
`dpkg-query`, Fedora via `rpm`, Arch via `pacman`, Alpine via `apk`.

### Les vingt-trois services empaquetés, mesurés sur quatre distributions

Quinze des trente-huit services s'installent par leur propre installeur, un
conteneur ou un binaire déposé — gitea, authelia, vaultwarden, ollama, jellyfin
et les autres — il n'y a donc pas de variance de distribution à mesurer pour
eux. Les vingt-trois autres viennent des dépôts, et chacun a été installé dans
des conteneurs Debian, Fedora, Arch et Alpine en demandant au gestionnaire de
paquets lui-même ce qu'il avait livré.

Quatre écarts en sont sortis, dont aucun n'était trouvable en lisant le code.

**Redis, c'est Valkey désormais.** `dnf install redis` et `pacman -S redis`
réussissent tous deux et laissent tous deux `/etc` vide ; la configuration qui
existe est `/etc/valkey/valkey.conf`. Sans le nom de paquet et sans le chemin,
redis est lu comme absent sur Fedora et Arch, et comme écoutant sur son port
par défaut sur Alpine, où c'est `/etc/redis.conf` qui sert.

**PostgreSQL garde sa configuration hors de `/etc` sur les hôtes rpm.**
`initdb` écrit `postgresql.conf` dans le répertoire de données —
`/var/lib/pgsql/data` sur RHEL, `/var/lib/postgres/data` sur Arch — et rien
n'existe sous `/etc/postgresql` là-bas. Le seul chemin Debian signifiait donc
que le port d'un service classé critique n'y était jamais lu.

**proftpd** est `/etc/proftpd.conf` sur Fedora et `/etc/proftpd/proftpd.conf`
partout ailleurs. **Apache** est `ports.conf` chez Debian, `httpd.conf` chez
Alpine, et `/etc/httpd/conf/httpd.conf` chez Fedora et Arch.

Vérifié de bout en bout avec les ports modifiés : redis sur 6399 lu sur les
trois familles non-Debian, apache sur 8081 lu sur Fedora et Alpine. Un échec
apparent n'en était pas un — le proftpd.conf de Fedora ne livre aucune
directive `Port`, donc retomber sur 21 est la bonne réponse, et ajouter la
directive a suffi pour que BOB la lise.

### openSUSE, la famille qui emprunte aux deux autres

La cinquième distribution revendiquée par BOB, et celle où aucune hypothèse ne
survit. Elle est à base rpm, donc `rpm -q` trouve ses paquets — mais elle nomme
son serveur web `apache2` comme Debian, garde la configuration sous
`/etc/apache2/` comme Debian, et place `Listen` dans un fichier qu'aucune des
quatre autres ne possède : `listen.conf`. Tous les chemins apache ajoutés
jusqu'ici le manquaient : le port était lu depuis rien.

Son redis ne livre que `redis.default.conf.template`, laissant l'administrateur
en copier un vers `/etc/redis/<instance>.conf` — un nom qu'aucun chemin fixe ne
peut prédire. Un glob y répond, borné à un niveau de répertoire pour que les
`includes/*.defaults.conf` livrés ne soient pas pris pour la configuration
active.

Vérifié de bout en bout sur Tumbleweed avec `Listen 8081`, `listen_port=2121`
et un fichier d'appoint `my.cnf.d` sur 3307 : tous lus, tous détectés via
`rpm`. Debian revérifié ensuite, les deux ajouts touchant des chemins qu'elle
apparie aussi.

Apache à lui seul nomme désormais quatre dispositions — le `ports.conf` de
Debian, le `listen.conf` d'openSUSE, le `httpd.conf` d'Alpine et l'arbre
`httpd` de Fedora/Arch — ce qui est la forme même du problème : cinq
distributions, et le port d'un service vit ailleurs sur presque chacune.

### Ce que BOB lit dans ces fichiers au-delà du port

Les chemins sont désormais justes ; restait ce que chaque check en fait. Deux
font davantage que trouver un port : `ssh` analyse sshd_config pour ses
verdicts de durcissement, et `ssl_certs` parcourt les configurations des
serveurs web pour savoir quels certificats sont réellement servis.

**SSH était déjà correct**, et mesuré plutôt que supposé. Fedora et Arch
livrent des fragments dans `/etc/ssh/sshd_config.d/`, inclus depuis le haut de
sshd_config, et OpenSSH retient la première valeur rencontrée — un fragment
l'emporte donc sur le fichier principal. Confronté à `sshd -T` après génération
des clés d'hôte, dans les deux sens : avec `PermitRootLogin no` dans le fichier
principal et `yes` dans un fragment, l'oracle dit oui et BOB dit oui ; à
l'inverse, les deux disent non.

**`ssl_certs` ne l'était pas.** Un certificat que BOB ne trouve jamais est un
certificat qui n'expire jamais, et il en manquait de deux façons, toutes deux
silencieuses — aucune erreur, aucun finding, une liste vide.

Le site nginx standard de Debian est `sites-enabled/default`, sans extension,
et le balayage cherchait `**/*.conf` : le seul fichier qui déclare le
certificat n'était jamais ouvert. Sur l'installation nginx la plus courante de
la distribution la plus courante, un certificat expirant n'était pas signalé.
Et seul `/etc/apache2` était parcouru : Fedora et Arch, qui gardent leurs
vhosts sous `/etc/httpd`, n'étaient pas examinés du tout.

Mesuré avec un vrai certificat à cinq jours de l'expiration, déclaré de la
façon ordinaire pour chaque serveur : les deux ne trouvaient rien, les deux le
rapportent désormais avec quatre jours restants. Les plafonds de nombre et de
taille de fichiers qui empêchent le balayage de parcourir un grand arbre sont
inchangés, et les répertoires ne sont plus passés à `read_text` maintenant que
le glob peut les apparier.

### La publication que les tests ont refusée

Le push a été rejeté par le garde de BOB lui-même, et PyPI n'a jamais vu la
version. Un test a échoué sur le runner après dix-sept passages verts en local.

`test_the_parse_matches_ss_line_for_line` est le contrôle différentiel de
v0.15.0 : il lit la sortie live de `ss` et vérifie chaque connexion analysée
contre sa colonne. Il reconstruit `adresse:port` et compare — or la grammaire
d'adresse unifiée plus tôt dans cette version retire les crochets d'un littéral
IPv6, ce qui est précisément ce qui permet à `[::1]` d'être reconnu comme
loopback. La reconstruction naïve ne correspondait plus.

Le point intéressant est pourquoi il a fallu un push pour le voir. Que ce test
exerce ou non la branche IPv6 dépend de la présence d'une connexion IPv6 sur la
machine au moment où la suite tourne. Le runner CI en avait une, la machine de
développement non. Un test qui lit le système vivant couvre ce que le système
vivant contient par hasard, ce qui n'est pas une propriété qu'on choisit.

La reconstruction tient compte des crochets, et la forme de colonne IPv6 a
désormais une couverture déterministe qui tourne partout — testée par mutation,
cache de bytecode vidé : remettre les crochets tue cinq tests, dont les deux
nouveaux.

### Deux angles mesurés et trouvés propres

**Contenu lisible mais corrompu** — le pendant fichier de l'angle « sortie
charabia ». sshd_config remplacé par du binaire aléatoire, une ligne tronquée,
des octets latin-1 et une ligne de 200 000 caractères : aucun plantage, aucune
trace, aucun verdict fabriqué au-delà du repli sur les défauts déjà décrit.
Délibérément non « corrigé » : une config qui parse à zéro directive est
indiscernable d'une config légitimement minimale, et une heuristique séparant
les deux produirait de fausses alertes sur des machines correctes.

**Les commandes qui pendent** au lieu d'échouer. `run_result` rapporte déjà le
chemin timeout comme un échec : un `ss` bloqué produit donc `ports.unreadable`
comme un `ss` absent. Bon à savoir en exploitation : chaque commande bloquée
coûte son timeout entier, et un audit face à plusieurs a mis un peu moins de
quatre minutes.

### Deux affirmations retirées

Rapportées comme défauts avant vérification, elles n'en étaient pas.
`auth_log` conserve son verdict « aucune connexion échouée » quand
`/var/log/auth.log` est illisible parce qu'il retombe sur journald et obtient
une vraie réponse — 27 jours analysés, réellement aucune connexion SSH. Et
`logrotate_ok` ne dépend pas du tout de `/etc/rsyslog.conf` ; l'association
venait d'un regroupement des findings par préfixe de clé plutôt que par ce que
chacun lit réellement.

### Une correction de méthode

Le premier passage de l'expérience sur les fichiers était invalide, et son
résultat a été rapporté avant que ce soit vu. Il montait un répertoire par bind
sur chaque chemin cible avec stderr supprimé ; or `mount --bind <rép> <fichier>`
échoue, donc BOB a lu les vrais fichiers du début à la fin, et le fait que
chaque cible rende un résultat identique à la référence était l'indice — lu sur
le moment comme « l'audit est totalement insensible à sa capacité de lecture »,
alors qu'il signifiait « rien n'a été modifié ». Refaite en montant un fichier
root en `0640`, réellement illisible dans le namespace, l'image était plus
étroite et précise : quatre verdicts, pas une insensibilité générale. C'est la
suppression de stderr qui l'avait masqué.

### Le correctif

`run_result()` rapporte séparément la sortie et le succès, sous la forme d'un `CommandResult(stdout, ok)`. `_run`
devient une enveloppe mince qui jette le drapeau : son contrat et son comportement sont donc inchangés pour la
cinquantaine d'appels où « vide » et « en échec » mènent à la même conclusion correcte. Les appelants qui ont besoin
de la distinction portent désormais un drapeau de lisibilité explicite dans leur snapshot, selon le motif établi par
les versions précédentes.

`services` n'avait besoin d'aucun drapeau : `all_listening_ports: set | None` encodait déjà l'inconnu par `None`, et
`check_rules` gardait déjà dessus. Le runner passait simplement un ensemble vide quoi qu'ait fait `ss`.

### Méthode

Le balayage qui a trouvé la sixième instance a remplacé l'inspection à l'œil : 25 commandes d'inspection mises en
échec à tour de rôle, l'audit complet lancé contre chacune, et les verdicts obtenus comparés à une référence — en
cherchant spécifiquement les affirmations rassurantes qui apparaissent *parce qu'*un outil est devenu aveugle. Il a
aussi établi que rien de pire ne se cache derrière : tout finding perdu quand un outil échoue est de niveau `ok` ou
`info`, donc aucun avertissement ni alerte n'est silencieusement supprimé.

Trois défauts de sonde ont été attrapés avant d'être rapportés comme findings, tous dans le banc de test et non dans
BOB : un montage bind échoué qui rendait un résultat apt vrai par accident, deux fixtures dont les deux variantes
finissaient sur la même valeur et ne discriminaient donc rien, et `"" in "=+-@"` — qui vaut `True` en Python et
signalait toute cellule CSV vide comme une formule.

### Modifié

- Nouveaux `bob/checks/_run.py::run_result()` et `CommandResult` ; `_run` préservé à l'identique.
- Nouveau `bob/checks/_run.py::unit_active_state()` ; `is_unit_active` préservé à l'identique.
- `ssh.active_unknown`, `ssh.config_unreadable`, `file_perms.sudoers_unreadable`,
  `user_accounts.no_passwd`, `umask.sources_unreadable`, `exposure.ssh_config_unknown`
  — six clés de plus pour les trois angles ajoutés, dans les deux locales.
- `SSHSnapshot.sshd_active_known` / `.sshd_config_readable`,
  `FilePermsSnapshot.sudoers_readable`, `UserAccountsSnapshot.passwd_readable`,
  `UmaskSnapshot.unreadable_sources` — là encore, défaut sur le cas lisible.
- `cron.unreadable_files`, `log_rotation.journald_conf_unreadable` — deux clés de plus,
  avec `CronAuditSnapshot.unreadable_files` et
  `LogRotationSnapshot.journald_conf_readable`.
- `_read_smb_conf` et `profiles._load_from_path` lèvent quand `configparser.read`
  ne rend aucun fichier lu ; `_read_cron_file` indique s'il a lu quelque chose.
- Nouveau `bob/checks/_run.py::path_exists()` ; les 30 sites `.exists()` des checks
  migrés, avec un test interdisant tout retour à l'appel nu.
- `log_rotation.logrotate_dir_unreadable` et `LogRotationSnapshot.logrotate_dir_listed`.
- La sonde sshd_config sépare absent / illisible / lisible.
- `audit.report_unavailable` : un rapport impossible à ouvrir dégrade vers le
  rapport nul au lieu d'interrompre l'audit.
- `UserConfig._load` et `EmailStore._load` attrapent `UnicodeDecodeError`.
- `ports.unreadable`, `ipv6.listeners_unknown`, `network_context.connections_unknown`,
  `exposure.open_ports_unknown`, `systemd_timers.unreadable` — cinq nouvelles clés, dans les deux locales.
- `PortsSnapshot.ports_readable`, `IPv6Snapshot.listeners_readable`,
  `NetworkContextSnapshot.connections_readable`, `SystemdTimersSnapshot.timers_readable` — toutes à `True` par
  défaut, les constructions existantes gardent donc leur sens.
- Le runner passe `all_listening_ports=None` quand la liste des sockets n'a jamais été lue.

### Contrat consommateur

Additif. Cinq nouvelles clés de finding peuvent apparaître ; aucune clé existante ne change de sens et aucun score
ne change — chaque nouveau finding est INFO sans déduction, car une absence de connaissance n'est pas une mauvaise
configuration. Les consommateurs qui filtrent sur `ports.*` doivent s'attendre à ce que `ports.unreadable` soit la
seule clé de cette section quand `ss` est indisponible.

**Tests** 7288 → **7560**.

---

## [v0.15.1] — 31-08-2026

**Une seconde chasse, pour savoir si la première a rendu BOB résilient. Six défauts de code et six inexactitudes documentaires, sur quinze angles dont onze sont revenus propres.**

v0.15.0 a corrigé 26 défauts de verdict en balayant six signatures dans tout l'arbre. Rejouer ces balayages ne ferait
que reconfirmer ses propres correctifs : cette passe attaque donc délibérément par des angles que la précédente n'a
jamais employés.

### L'angle neuf principal : des contrôles qui se contredisent

BOB possède des surfaces qui se recouvrent — `firewall`, `firewall_stack`, `iptables_nftables` et `ports` décrivent
tous le pare-feu ; `ipv6` et `hardening` lisent tous deux la pile IPv6 ; `services` et `ports` classent tous deux
l'exposition. Un audit module par module ne peut pas voir une contradiction entre deux d'entre eux, puisque chacun est
cohérent avec lui-même. Deux contrôles qui disent des choses différentes de la même machine forment un défaut par
construction, quel que soit celui qui a tort.

### « Aucun problème » à propos d'un jeu de règles jamais listé

Première trouvaille du nouvel angle, et elle vient de la comparaison de deux
contrôles plutôt que de l'audit de l'un d'eux. `firewall_stack` et
`iptables_nftables` décrivent tous deux les pilotes de pare-feu ; interrogés sur
la même machine, l'un rapportait une requête refusée et l'autre une pile saine.

`iptables -L` et `nft list ruleset` exigent tous deux CAP_NET_ADMIN et écrivent
leur refus sur stderr, laissant stdout vide. `_run` jette le code de retour :
`_has_user_nft_rules("")` renvoyait donc False, `nftables_active` devenait False,
et le contrôle émettait `[OK] firewall_drivers.no_issues` — un certificat de
bonne santé explicite pour un jeu de règles jamais vu.

`iptables_nftables` avait été corrigé précisément pour cela en v0.15.0.
`firewall_stack` avait été examiné dans le même cycle, mais seulement pour son
analyse de lignes : la question ne lui a jamais été posée. **Un module examiné
pour une signature n'est pas un module écarté.**

Le discriminateur est celui déjà établi : un `iptables -L` qui fonctionne
imprime toujours ses en-têtes de chaîne, même sans règle chargée ; un binaire
installé plus une sortie vide signifient donc une requête refusée. `nft list
ruleset` n'imprime rien pour un jeu réellement vide et ne peut pas distinguer
seul — mais les deux commandes exigent la même capacité, donc iptables répond
pour les deux.

L'une des gardes vérifie que les deux modules s'accordent, ce qui est la
propriété qui a fait surgir le défaut.

**Tests** 7220 → **7288**.

### Trois copies privées de plus de la grammaire UFW

v0.15.0 a unifié `ports` et `services` sur `bob/checks/_ufw.py` après avoir
constaté qu'ils se contredisaient. Il n'a jamais balayé les *autres* copies. Il y
en avait trois, et la troisième a été trouvée par la garde écrite pour les deux
premières, pas à la main.

**`ipv6._extract_ufw_v6_covered`** avait été examiné pendant v0.15.0 et écarté
parce qu'il était correctement ancré sur le numéro de règle. L'ancrage n'est pas
la complétude : il ne reconnaissait qu'un port nu, si bien que `OpenSSH (v6)`,
`6000:6007/tcp (v6)` et `80,443/tcp (v6)` se lisaient tous comme *aucune règle
v6*. Mesuré sur ces trois lignes, il renvoyait un ensemble vide — chacun de ces
ports levait donc `ipv6.port_no_v6_rule`, un avertissement avec déduction, sur
une machine qui avait bel et bien les règles.

**`ddns._find_open_ports`** n'avait jamais été examiné. Cherchant sur la ligne un
unique `\b(\d+)/(tcp|udp)\b`, une plage ne donnait que sa borne haute et une
liste que son dernier élément ; un profil applicatif ne donnait rien : sur quatre
règles couvrant douze ports, il en trouvait deux. Il testait aussi la restriction
de source sur toute la ligne, si bien que `ufw allow from any to 192.168.1.5 port
8080` — destination privée, source publique — était classé restreint. Celui-ci
sous-déclare les ports ouverts, c'est-à-dire la direction rassurante.

**`firewall._check_orphan_rules`** a été trouvé par la nouvelle garde, qui exige
qu'aucun module n'analyse `ufw status numbered` sans la grammaire partagée. Même
défaut : deux ports orphelins signalés sur huit. Une règle orpheline est un trou
de pare-feu laissé par un service qui ne tourne plus : sous-déclarer est
silencieux, pas bruyant. `firewall.py` n'a désormais plus aucune expression
régulière de règle en propre — le filtre de ligne et le retrait d'index sont eux
aussi passés dans `_ufw.is_rule_line` et `_ufw.strip_rule_index`.

La garde est le point important. Six copies existaient ; en unifier deux et
vérifier le reste à l'œil en a laissé trois. C'est un test qui échoue sur
*n'importe quel* module portant la grammaire en privé qui a refermé le sujet.

### Une correction de la méthode de mutation elle-même

Une mutation a semblé survivre, et la rejouer à la main donnait une réponse
différente de celle de la suite. La cause était un `__pycache__` périmé :
restaurer le fichier source n'invalide pas toujours le bytecode en cache, si bien
qu'un verdict peut être mesuré contre le code muté alors que la mutation a
disparu. Les trois mutations de ce changement ont été rejouées avec purge du
cache entre chacune — les trois tuent. Consigné parce qu'un résultat de mutation
mesuré contre le mauvais bytecode ne prouve rien, ce qui est exactement le même
mode de défaillance qu'une garde qui passe pour la mauvaise raison.

### Deux rapports affichaient un `{pct}` et un `{path}` littéraux

Encore un angle neuf : confronter chaque site d'appel `t("clé", **kwargs)` aux
variables que son gabarit de locale contient réellement. `i18n.t` attrape le
`KeyError` qui en résulte et renvoie le gabarit brut : la défaillance est donc
invisible à l'exécution et visible seulement pour l'opérateur, sous forme
d'accolade dans son rapport.

Deux cas sur 399 sites d'appel :

* `disk.partition_critical_reason` — la **raison de déduction**, c'est-à-dire ce
  que le détail de score affiche pour expliquer un point perdu, se rendait en
  « Partition /data is {pct}% full ». Le message de finding juste au-dessus
  passait `pct` correctement ; seule la raison ne le faisait pas, donc le
  rapport donnait le pourcentage et l'explication de la déduction non.
* `file_perms.ssh_host_key_perms_detail` — se rendait en
  « Corriger : sudo chmod 600 {path} », demandant à l'opérateur de lancer une
  commande impossible à copier, alors que le champ `cmd` du même finding portait
  le bon chemin.

Les deux se rendent maintenant dans les deux langues, vérifié de bout en bout et
non au site d'appel. Passer une variable qu'un gabarit n'utilise pas est
inoffensif — `str.format` ignore les extras — et trois appels le font
délibérément : la garde ne vérifie donc que la direction manquante.

### Quatre angles de plus, tous propres

* **Pureté des `check_*`.** Chaque `check_xxx` a été affirmé pur tout au long de
  v0.15.0 sans jamais être vérifié. Un balayage AST cherchant `_run`, `open`,
  `read_text`, `stat`, `glob` et consorts dans un corps de `check_*` en trouve
  **zéro** — la séparation snapshot/contrôle tient par mesure, pas par
  convention.
* **Possibilité de suppression.** Les 399 clés littérales de findings de l'arbre
  satisfont `is_valid_ignore_key`, sur 51 préfixes : aucun finding qu'un
  opérateur ne puisse faire taire avec `--ignore`.
* **Robustesse des analyseurs.** 66 parseurs à argument unique contre quatorze
  charges hostiles — une ligne de 1 Mo, des octets nuls, des surrogates, des
  séquences ANSI, une bombe regex, 500 niveaux de `../`. Aucun blocage, aucun
  plantage sur un chemin atteignable.
* **Idempotence.** Trois audits consécutifs produisent des findings, déductions
  et dégradations identiques. Une différence est bien apparue — un compte de
  services de 44 contre 45 — et a été remontée jusqu'à `user@1000.service` qui
  démarre et s'arrête entre les exécutions, confirmé en voyant le compte bouger
  dans les deux sens sur une machine par ailleurs au repos. L'audit reflétait
  correctement le système ; c'est le système qui changeait.

### Cinq angles de plus, tous propres

* **Plafonds par outil.** Trois contrôles déclarent un plafond (`clamav`,
  `file_integrity`, `rootkit`, 1 point chacun). Avec trois déductions rootkit, le
  score brut tombe à 7 et le score rapporté reste à 9, chaque ligne plafonnée est
  marquée *[capped — tool limit reached]*, et un INFO indique
  « 3 pt raw → 1 pt counted ». L'écart entre les deux nombres n'est pas seulement
  calculé juste, il est montré.
* **Application du profil.** Aucune déduction n'atteint le moteur sans passer par
  `apply()`, vérifié en AST — aucun appel direct à `_apply_deduction` hors de
  `ScoreEngine`. Côté comportement, une clé surchargée retombe en INFO sans
  déduction sur `desktop`, `container` et `workstation`, et reste un WARN à
  2 points sur `server`, tandis qu'une clé non surchargée est inchangée. Le
  câblage de v0.14.0 tient.
* **`--check` / `--skip`.** `--check=ssh` donne ssh plus exactement les dix
  sections toujours actives, conformément aux « 38 filtrables + 10 always-on »
  documentés ; `--skip=ssh` la retire ; `--check=ssh,disk` donne les deux.
* **Export CSV.** Les quatre préfixes de formule tableur (`=`, `+`, `-`, `@`)
  sont neutralisés par une apostrophe ; séparateurs, guillemets, sauts de ligne
  et retours chariot intégrés laissent le nombre de lignes correct.
* **Rapport détaillé `-d`.** Durci en v0.7.3 et revérifié ici : `<script>` et
  `<img onerror=>` arrivent échappés en texte inerte, et `_safe_url` ramène
  `javascript:`, `data:` et `vbscript:` — ainsi que les URL relatives — à `#`.

Une mesure de ce lot a failli devenir une fausse découverte : le cas
`<img onerror>` a déclenché un détecteur grossier cherchant la chaîne
`onerror=`, qui figure aussi dans la forme échappée. Le corps rendu est
`&lt;img src=x onerror=alert(1)&gt;`, inerte. Vérifié avant d'être rapporté,
comme les cinq autres artefacts de harnais de ce cycle.

### La passe documentaire : six chiffres que personne ne vérifiait

Reportée de v0.15.0, où la question « la documentation est-elle cohérente
maintenant ? » a reçu une réponse mesurée plutôt qu'affirmée. Elle ne l'était
pas.

| Affirmation | Où | Réalité |
|---|---|---|
| « contient **exactement 2008** clés » | `README_DEV` | 2034 |
| « 1941 clés × 2 locales » | `TUTORIAL` | 2034 |
| « 168 clés en v0.8.x » | `TUTORIAL` | 169, et sept versions de retard |
| « variantes par profil (19 clés × 3) » | `README_DEV` | 70 |
| « 19 clés » | `README_TECH` | 70 |
| `bob/checks/_ufw.py` | arborescence `README_DEV` | absent |

Deux étaient présentées comme vérifiées — « contient exactement … (vérifié par
le test de stricte parité) » — et le test de parité vérifie que EN correspond à
FR, pas que le nombre annoncé corresponde au fichier. Une phrase qui s'appuie
sur une garantie ne la couvrant pas, c'est la forme même des défauts de code
corrigés dans ce cycle.

L'omission dans l'arborescence compte plus qu'il n'y paraît : `_ufw.py` est
l'endroit où vit la grammaire des règles UFW après y avoir unifié cinq copies,
et un développeur lisant l'arbre n'aurait pas su que le module existe.

Les chiffres historiques sont laissés tels quels. `README_TECH` dit « Baseline
history: v0.7.0 audit = 117 keys / 30 prefixes », énoncé sur v0.7.0 et correct
comme tel.

### `SECURITY.md` décrivait une garantie plus large qu'elle ne l'était

La section « Rendu de texte non fiable » affirmait que le point de passage
`Finding.__post_init__` couvrait « les sorties terminal, JSON, CSV, Markdown et
HTML … par une seule garantie ». Vrai des caractères de contrôle, et cela invite
à lire que ces sorties sont couvertes *point* — ce qui est précisément ce qui a
laissé les trous de balisage Markdown et Slack passer inaperçus jusqu'à ce que
v0.15.0 aille regarder.

La section décrit désormais deux couches et dit pourquoi elles ne peuvent pas
n'en faire qu'une : la couche 1 retire les octets de contrôle à la construction
et atteint toutes les sorties ; la couche 2 échappe le balisage au rendu et est
nécessairement propre à chaque format, car ce qui constitue du balisage dépend
de la destination, et échapper à la construction corromprait le terminal et le
JSON. Un tableau donne le traitement de chaque écrivain, Slack compris — que la
section ne mentionnait pas du tout.

### Une garde pour la prose

Les gardes documentaires existantes vérifient la cohérence des versions, les
liens relatifs, la parité EN/FR et le compte de tests. Aucune ne lit une phrase
pour la confronter au code, ce qui explique que six chiffres aient dérivé sans
bruit. `tests/test_v0151_doc_prose_figures.py` vérifie désormais le compte de
clés de locale, les comptes de clés et de préfixes explain, le compte de
variantes de profil contre le mécanisme réel `_has_profile_variants`, le compte
du registre de services, et la présence de chaque helper partagé
`bob/checks/_*.py` dans l'arborescence. Quatre mutations injectées, quatre kills.

### Passe documentaire reportée de v0.15.0

Cinq inexactitudes mesurées, trouvées en répondant à « la documentation est-elle cohérente maintenant ? » — la réponse
était non.

---

## [v0.15.0] — 31-08-2026

**Exactitude des verdicts. Vingt-six défauts corrigés dans les contrôles et les écrivains de sortie, chacun mesuré contre l'outil qui fait autorité sur le fichier ou la commande plutôt que déduit.**

L'objectif du cycle, fixé avant d'écrire la moindre ligne de code : rendre juste ce que BOB *affirme*, avant
d'ajouter de nouvelles déductions. Un verdict faux discrédite plus l'outil qu'un verdict manquant.

### Méthode

Chaque correctif est testé en différentiel contre l'analyseur qui fait autorité sur le fichier :

| Surface | Oracle |
|---------|--------|
| `sshd_config` | `sshd -T` |
| `ssh_config`  | `ssh -G`  |
| `sudoers`     | `cvtsudoers -f json` |
| `ufw status`  | formes de règles produites par `ufw` lui-même |

Les attentes des fichiers de garde sont relevées sur ces oracles plutôt qu'écrites à la main : elles consignent donc
ce que le système accorde, et non ce à quoi la ligne de configuration ressemble.

### Une classe de défaut domine : le commentaire en fin de ligne

Les motifs d'un contrôle avaient été écrits sur la forme *propre* d'une ligne et cessaient de correspondre dès qu'un
opérateur ajoutait un commentaire. Commenter ses règles de sécurité est une bonne pratique : **plus l'administrateur
est rigoureux, plus la détection échoue**.

- **SSH, côté serveur** (`bob/checks/ssh/_parsers.py`) — un commentaire en ligne était emporté dans la valeur analysée.
- **SSH, côté client** (même module) — même omission sur `ssh_config`, et `StrictHostKeyChecking off/false` ainsi que
  `ForwardAgent/ForwardX11 true` n'étaient pas reconnus comme les orthographes qu'OpenSSH accepte.
- **Pare-feu** (`bob/checks/firewall.py`) — `ufw allow ... comment 'x'` ajoute `# x` à chaque ligne de
  `ufw status numbered`. `_check_open_any` est ancré sur la fin de ligne : `Anywhere ALLOW IN Anywhere # temporaire`
  — tous les ports depuis toutes les sources, la règle la plus dangereuse qu'UFW puisse contenir — ne produisait
  **ni ALERTE ni déduction, rien du tout**. `_check_ipv6_coverage` présentait une variante : il comptait
  `"(v6)" in line`, donc un commentaire mentionnant `(v6)` supprimait l'avertissement d'absence d'IPv6.
- **Sudoers** (`bob/checks/file_perms.py`) — `#` ouvre un commentaire *n'importe où* sur une ligne sudoers, y compris
  collé (`ALL#tmp`) ; `NOPASSWD: ALL # temporaire` était donc classé comme un octroi restreint : un WARN assorti
  d'une déduction de 2 points devenait un INFO sans score. Deux autres manques sont sortis du même audit : les
  continuations par barre oblique inverse étaient lues ligne par ligne, donc une règle coupée entre `NOPASSWD:` et sa
  commande était invisible ; et `#1000 ALL=(ALL) NOPASSWD: ALL` — la forme utilisateur par uid numérique — était
  purement et simplement ignorée comme une ligne de commentaire.
- **Mises à jour automatiques** (`bob/checks/updates.py`) — la direction inverse, et la plus dangereuse : ici le commentaire n'a pas caché un problème, il a inventé une garantie. `apt.conf` accepte trois syntaxes de commentaire (`//`, `/* */`, `#`) et `20auto-upgrades` est précisément le fichier qu'un administrateur neutralise en commentant la ligne. Le motif étant appliqué au texte brut, BOB annonçait les mises à jour automatiques **actives** sur une machine où apt ne lit rien du tout. Vérifié contre `apt-config dump` pour les trois syntaxes.

Chaque correctif est testé par mutation : le défaut est réinjecté et la nouvelle garde doit échouer.

### La boucle principale de l'audit n'avait jamais été exécutée par un test

Trois fichiers de test atteignent `run_checks` via `ast` et affirment des
choses sur son source. Aucun ne l'exécutait. La barrière de faute de v0.14.1,
les 38 sites d'appel de section et les fabriques de snapshot qui alimentent
chaque contrôle n'étaient donc couverts que par inspection — c'est ainsi
qu'une barrière se voit vérifiée *existante* sans jamais être vérifiée
*fonctionnelle*.

`tests/test_v0150_runner_end_to_end.py` exécute le véritable audit en
processus, sans privilèges et isolé de la configuration de l'utilisateur. Sans
privilèges est le cas le plus dur : la plupart des contrôles se heurtent à
EACCES sur `/etc/shadow` et consorts, ce à quoi servent précisément les
chemins de dégradation.

Il a trouvé un défaut dès sa première exécution. **Cinq findings étaient
construits sans clé** — deux dans `ddns`, trois dans `logs`. Un finding sans
clé est inatteignable par `--explain`, ne peut pas être supprimé par
`--ignore`, n'est pas suivi par la récurrence, et parvient anonyme à la sortie
JSON. 275 des 280 sites de construction passaient une clé : la signature d'un
invariant tenu par convention plutôt que par construction, et les conventions
dérivent un site d'appel à la fois. L'exécution live en a révélé un sur cinq ;
les quatre autres sont sur des chemins que cette machine ne prend pas, d'où
une garde statique qui les couvre tous.

L'exécution vérifie aussi qu'aucun finding ni aucune ligne affichée ne se rend
sous la forme d'une clé nue `[une.cle]` dans l'une ou l'autre langue — le mode
de défaillance corrigé en urgence par v0.9.1, que les gardes statiques de
locale avaient laissé passer.

### Le cœur toujours-actif interrompait l'audit ; il se dégrade désormais

v0.14.1 a posé une barrière de faute sur les sections distribuées par `_sec`, et
documentait le cœur toujours-actif comme délibérément exclu : c'est « un
pipeline de données, pas un ensemble de sections », et y avaler une panne
laisserait le code aval lire des noms jamais liés.

Confronté au flux de données réel, cet argument couvre deux des douze collectes
du cœur. Les dix autres sont des sections ordinaires qui ne sont simplement pas
filtrées par profil — rien hors de leur propre bloc ne les lit. En injectant une
erreur de décodage dans chaque collecteur, avant ce changement, l'audit entier
était perdu dans sept cas sur huit, et perdu *tard* : le snapshot fail2ban
interrompait tout après **29 962 octets** déjà parvenus à l'opérateur, qui
obtenait ensuite un code 3, sans score, sans résumé et sans JSON. La panne que
v0.14.1 entendait supprimer restait vivante dans la moitié du runner que la
barrière n'atteignait pas.

`with _core(section)` couvre maintenant `firewall_iptables`,
`firewall_drivers`, `network_context`, `ipv6`, `ddns`, `logs`, `docker`,
`virtualization` et `hardening` ; `fail2ban` passe à la forme fabrique
paresseuse et hérite de la barrière `_sec`. Les collectes dont le snapshot est
renvoyé dans `ChecksResult` sont liées à une valeur par défaut avant le bloc
protégé, de sorte qu'une panne dégrade au lieu de laisser le nom non lié.

`fw_status` et `ports_snapshot` restent non protégés, et la raison n'est pas la
cascade de `NameError` — c'est l'honnêteté du verdict. Presque tous les
contrôles en aval les lisent. Y substituer une valeur vide ne dégraderait pas
l'audit, cela le ferait **mentir** : une table de ports illisible se rendrait en
« rien n'écoute », un pare-feu illisible en pare-feu sans règles. **Un audit
échoué que l'opérateur voit vaut mieux qu'un audit propre qui est faux.** La
limite est verrouillée par un test pour qu'on ne la franchisse pas par souci de
rangement.

### Politique de mots de passe : trois fichiers, trois autorités, trois désaccords

`bob/checks/password_policy.py` lit `/etc/login.defs`,
`/etc/pam.d/common-password` et `/etc/security/pwquality.conf`. Il était en
désaccord avec le véritable propriétaire des trois, et l'erreur commune était de
lire la *première* correspondance.

**`login.defs` et `pwquality.conf` retiennent la dernière valeur.** Vérifié avec
le `useradd --prefix` de shadow lui-même sur un `login.defs` dupliqué, en
relisant le champ effectivement écrit dans shadow, et en appelant libpwquality
1.4.5 par ctypes sur un `pwquality.conf` dupliqué. Ajouter la valeur durcie à la
fin du fichier — ce qu'écrivent tous les guides de durcissement, et ce que fait
`echo >>` — laissait BOB rapporter la valeur que l'opérateur venait justement
d'écraser. Les deux directions sont fausses et la seconde est pire : une distro
livrant `PASS_MAX_DAYS 90` avec `99999` ajouté n'a plus aucune expiration, et
BOB annonçait 90.

**`/etc/security/pwquality.conf.d/` n'était jamais ouvert.** libpwquality lit
d'abord le répertoire de dépôts, en ordre ASCII, puis le fichier principal.
Debian livre `pwquality.conf` avec tous les réglages commentés, ce qui fait du
dépôt l'endroit où le durcissement atterrit réellement. L'ordre d'analyse a été
mesuré, non repris de la page de manuel dont la formulation admet les deux
lectures : un namespace de montage avec un `/etc/security` synthétique, et la
bibliothèque interrogée directement.

**Les piles PAM se coupent en plusieurs lignes.** `pam.conf(5)` prend justement
une ligne `pam_pwquality.so` coupée comme exemple. Lue ligne par ligne, le
module et le `minlen=` qu'on lui donne se retrouvent sur des lignes différentes
et ne se rencontrent jamais : BOB détectait le module de qualité et annonçait
aucune longueur minimale.

`join_continuations` passe dans `bob/checks/_run.py` et est désormais partagé
avec l'analyseur sudoers. C'est le fond du sujet plus qu'un rangement : chaque
défaut de ce cycle vient d'un traitement de configuration ligne à ligne réécrit
une fois par contrôle, juste dans certaines copies et oublié dans d'autres.

Une question reste ouverte plutôt que devinée : savoir si un `minlen=` inline
PAM prime sur `pwquality.conf` ou l'inverse. `pam_pwquality.so` n'est pas
installé ici, donc il n'existe pas d'oracle local, et ce cycle ne troque pas un
verdict mesuré contre un verdict supposé.

### L'analyseur `ss` : un résultat négatif, consigné comme tel

Confronté aux tables de sockets du noyau lui-même —
`/proc/net/{tcp,tcp6,udp,udp6}`, filtrées sur les états que `ss -l` rapporte —
BOB était exactement d'accord : 33 sockets, 20 couples (proto, port) distincts,
rien de manqué dans un sens comme dans l'autre. L'analyseur est sain, et cela
mérite d'être écrit aussi clairement qu'un défaut.

Un écart est tout de même sorti des formes que cette machine ne produit pas. Le
`%scope` était détaché de l'adresse vers `iface` pour IPv4 et pas pour IPv6 : le
champ JSON `address` valait donc `fe80::1%eth0` et `iface` revenait vide — la
branche IPv4 honorait la docstring de la fonction, la branche IPv6 non, en
silence. Aucun verdict n'a bougé, et c'est précisément pourquoi l'écart a
survécu : une adresse scopée ne correspondait de toute façon jamais au motif
« toutes interfaces », donc les deux chemins arrivaient à la bonne réponse et
l'un d'eux y arrivait pour la mauvaise raison.

La comparaison live avec le noyau n'est **délibérément pas** dans la suite. Elle
comporte une course — une socket peut s'ouvrir ou se fermer entre l'appel à `ss`
et la lecture de `/proc` — et une garde qui échoue pour des raisons étrangères au
code est une garde qu'on apprend à ignorer. Ce sont les formes de sortie
déterministes qui sont verrouillées à la place.

### Un contrôle noyau absent était rapporté comme activé

`_sysctl_int(key, default)` renvoyait un défaut *durci* dès que `/proc/sys`
n'était pas lisible — `ptrace_scope` retombait à 1, `kptr_restrict` à 1, l'ASLR à
2. `CONFIG_SECURITY_YAMA` est une option de compilation, et le sysctl est tout
aussi absent quand `yama` ne figure pas dans la liste `lsm=` au démarrage : sur
un tel noyau, BOB affichait

    [OK] kernel_hardening.ptrace_ok    ptrace restreint (scope=1)
    [OK] kernel_hardening.kptr_ok      pointeurs noyau masqués

Aucune de ces protections n'existait. Annoncer un contrôle absent comme activé
est la pire réponse que puisse donner un outil d'audit, et c'était ici la réponse
*par défaut* — atteinte par n'importe quel échec de lecture : réglage absent,
`/proc` restreint, ou lecture simplement refusée.

Chaque champ vaut désormais `None` par défaut, c'est-à-dire « non lu » : une
réponse distincte de toute valeur, et jamais un substitut. Les réglages que le
noyau n'expose pas sont signalés une fois, ensemble, en INFO — un contrôle absent
n'est ni une réussite ni un échec chiffrable. Cinq tests de
`test_kernel_hardening.py` verrouillaient les anciens défauts et verrouillaient
donc le défaut lui-même ; ils sont remplacés par un seul, qui exige que rien ne
soit supposé avant lecture.

Là où les réglages existent, BOB était déjà exact — vérifié contre `sysctl -n`
pour les cinq.

### Le même défaut, sur dix réglages, dans la section durcissement

Un balayage du motif trouvé dans `kernel_hardening` l'a retrouvé dans
`bob/checks/hardening.py`, en plus large. `_read_sysctl_int(key, default)` et
`_read_sysctl_bool(key, default)` renvoyaient le défaut à tout échec de lecture,
et les dix sites d'appel passaient tous la valeur *durcie* — rp_filter 1,
accept_redirects False, log_martians True, syncookies 1, et ainsi de suite. Un
`/proc/sys` illisible produisait donc une pile réseau parfaitement durcie : dix
réussites pour dix paramètres que BOB n'avait pas lus, sous l'en-tête
« ANALYSE DU DURCISSEMENT SYSTÈME ».

Le déclencheur réaliste n'a rien d'exotique. Démarrez avec `ipv6.disable=1` et
`/proc/sys/net/ipv6` n'existe pas du tout : `net.ipv6.conf.all.accept_redirects`
était alors répondu par le seul défaut — alors que le contrôle IPv6 de BOB traite
déjà une pile désactivée comme un état ordinaire. L'outil se contredisait
lui-même.

Chaque champ vaut désormais `None` par défaut. Le bloc JSON `hardening` reflète
un paramètre non lu par `null` au lieu d'affirmer une valeur jamais observée —
strictement plus d'information qu'avant, et uniquement là où la valeur
précédente était fabriquée.

### Avec UseDNS activé, une machine ne signalait aucune connexion SSH publique

Le balayage qui a produit les deux correctifs sysctl a passé en revue les 100
gestionnaires d'exception de l'arbre qui renvoient une valeur substantielle. La
plupart échouent dans la direction alarmante, ce qui est correct pour un
auditeur : `DockerPort.is_public` suppose public sur une adresse non reconnue,
`_has_shell_ops` suppose dangereux sur un guillemetage malformé,
`_read_kernel_ipv6` suppose activé. Un seul faisait l'inverse.

`auth_log._is_private` renvoyait True — « privé » — pour tout ce que
`ipaddress.ip_address()` ne savait pas analyser, afin d'écarter le bruit du
résumé. Mais la source est capturée par `from\s+(\S+)\s+port` dans une ligne
sshd, et sshd y journalise un **nom d'hôte** dès que `UseDNS` est actif. Sur une
telle machine, chaque connexion distante donnait un non-IP, était classée
interne, et `auth_log.public_login` ne pouvait pas se déclencher. Une machine
acceptant des connexions SSH depuis Internet s'entendait dire qu'elle n'en
acceptait aucune.

Un nom non résolu est inconnu, pas interne. Deux fonctions du même outil
répondant en sens inverse à « cette adresse est-elle publique » : voilà comment
l'une des deux finit par avoir tort, et c'était celle-ci. `workstation.lan` sera
désormais listé, ce qui est l'erreur la moins chère : une fausse alerte nommant
une source que l'opérateur peut lire se rattrape, un silence non. Ce compromis
est verrouillé par un test pour qu'il reste une décision et non un accident.

### L'audit disque ignorait entièrement les racines ZFS

Les pourcentages étaient exacts — vérifiés contre `os.statvfs`, l'appel système
que `df` effectue lui-même, sur chaque partition de cette machine. Les deux
défauts portaient sur les lignes *retenues* et sur la *portion* de chaque ligne
lue.

Le filtre était `device.startswith("/dev/")`, sous un commentaire affirmant
qu'il couvrait la liste des pseudo-systèmes de fichiers. Il couvrait trop. Un
dataset ZFS s'appelle `rpool/ROOT/pve-1`, pas `/dev/…` : sur toute machine à
racine ZFS — Proxmox par défaut, Ubuntu en option d'installation — le système de
fichiers racine était écarté de l'audit et un pool à 93 % ne produisait aucun
finding. Le filtre travaille désormais sur le *type* de système de fichiers, via
`df -PT`, ce que la docstring affirmait depuis toujours. C'est une liste
d'exclusion à dessein : c'est une liste d'inclusion qui a échoué ici, donc un
type auquel personne n'a pensé est maintenant audité au lieu d'être écarté en
silence. Les types réseau y figurent explicitement plutôt que par accident — un
partage NFS plein est un vrai problème, mais ce n'est pas le disque de cette
machine.

Second défaut, même fonction : `df` affiche les points de montage sans
échappement et `line.split()[5]` n'en prend qu'un mot. Un disque monté sur
`/media/so6/My Passport` était rapporté comme `/media/so6/My` — un chemin qui
n'existe pas, dans un finding annonçant à l'opérateur qu'il est plein à 95 %.

### Un service de sécurité en échec était invisible pour le contrôle qui
### signale les services de sécurité en échec

`systemctl list-units` préfixe d'un glyphe d'état toute unité que systemd juge
« pas en ordre », ce qui décale toutes les colonnes d'un cran. Le glyphe dépend
de la locale : `●` en UTF-8, `*` sous l'environnement `LC_ALL=C` qu'utilise
`_run` par défaut — les captures de BOB portent donc l'astérisque. 27 unités de
la machine de développement s'affichent ainsi.

`services_state` lisait `split()[0]` comme nom d'unité et `[2]` comme état :

    * auditd.service  loaded failed failed Security Auditing Service
      unité = "*"        -> pas un service de sécurité connu, ignoré
      état  = "loaded"   -> ni inactive ni failed, ignoré

Un service de sécurité activé mais en échec est exactement ce que ce contrôle
existe pour signaler, et exactement le cas que systemd marque du glyphe. Le
contrôle ne voyait pas son propre sujet. `systemd_hardening._running_services`
faisait la même lecture.

L'outil le savait déjà : `socket_units` cherche le token par son suffixe
`.socket` et documente le glyphe en commentaire, `systemd_timers` passe par des
regex. Deux analyseurs sur quatre le traitaient — la même forme que la famille
du commentaire en fin de ligne plus tôt dans ce cycle, où `_check_duplicates`
dépouillait les commentaires et pas ses voisins. `strip_unit_glyph` vit
désormais dans `bob/checks/_run.py` et gère les deux glyphes.

Également dans `systemd_hardening` : le plafond `_MAX_UNITS` s'appliquait à la
sortie de `systemd-analyze` *avant* le filtrage sur les services actifs. Sur une
machine comptant plus d'unités analysées que le plafond, il bornait donc quels
services actifs étaient examinés — par ordre alphabétique — au lieu de borner le
nombre de résultats conservés. On filtre d'abord, on plafonne ensuite.

Le cadrage lui-même a été vérifié exact contre
`systemd-analyze security --json=short` et `systemctl list-units` : 44 actifs, 74
analysés, 44 retenus, aucune divergence.

### Un compte verrouillé aujourd'hui était rapporté comme sain

Les deux attentes viennent ici de l'outillage de shadow lui-même, exécuté contre
un `/etc/shadow` synthétique sous namespace utilisateur, plutôt que déduites du
format.

`chage(1)` définit le champ d'expiration comme « la date **à laquelle** le compte
de l'utilisateur ne sera plus accessible ». BOB testait
`0 < expire_days < today_days` — un `<` strict — donc un compte expirant
aujourd'hui était annoncé sain le jour précis où l'opérateur a le plus besoin de
l'apprendre. C'est désormais `<=`, et `chage` et BOB s'accordent sur la limite
dans les deux sens.

Le second cas est plus intéressant parce que la bonne réponse n'était pas de
trancher. BOB ignorait un champ d'expiration valant exactement `0`. `shadow(5)`
indique que cette valeur « ne devrait pas être utilisée car elle est interprétée
soit comme une absence d'expiration, soit comme une expiration au 1er janvier
1970 », et `chage` sur ce système retient la seconde lecture — il affiche
**Jan 01, 1970**. La possibilité de se connecter dépend donc de
l'implémentation.

Choisir une lecture en silence aurait été tout aussi peu vérifié que le silence
précédent. Une configuration dont l'effet dépend de l'implémentation est un
finding en soi : elle est maintenant signalée comme ambiguë, en INFO seulement,
avec les deux lectures nommées et les deux façons de la résoudre
(`chage -E AAAA-MM-JJ` ou `chage -E -1`). Deux clés de locale, EN+FR.

Constaté et délibérément non modifié : le contrôle lit directement `/etc/passwd`
et `/etc/shadow`, donc les comptes servis par un backend NSS — LDAP, SSSD,
systemd-homed — sont hors de sa portée, y compris un compte UID 0 qui y serait
défini. `getent passwd` les verrait, mais changer de source change ce que ce
contrôle signifie sur une machine jointe à un annuaire : c'est une décision à
prendre délibérément, pas un effet de bord d'une correction de bug.

### Un certificat encore valide 23 heures était rapporté EXPIRÉ

Neuf certificats ont été forgés aux limites et chaque verdict comparé à
`openssl x509 -checkend 0`, qui fait autorité sur la validité courante d'un
certificat.

`days_left` est un delta de temps tronqué par plancher, et Python plafonne aussi
les deltas négatifs vers le bas :

    expire dans 23h        ->  0
    expire dans 1h         ->  0
    expiré il y a 1 minute -> -1
    expiré il y a 12h      -> -1

`days <= 0` couvrait donc toute la dernière journée d'un certificat *encore
valide*. BOB levait `ssl_certs.expired` — une ALERTE, 2 points de déduction, et
un message annonçant qu'il a expiré « il y a 0 jour » — pour un certificat
qu'openssl accepte. Deux des neuf cas étaient faux, tous deux dans la direction
alarmante : rattrapable, mais c'est une affirmation fausse que l'opérateur
réfute en une commande, et c'est ainsi qu'un outil perd son crédit.

`days == 0` tombe désormais dans la branche critique. Toujours une ALERTE,
toujours une déduction — adoucir la formulation ne doit pas adoucir l'urgence, et
un test le verrouille — mais l'affirmation est vraie. `days < 0` signifie
exactement « la date notAfter est passée » : la nouvelle limite n'est pas un
seuil réglé, c'est l'arithmétique.

L'analyseur lui-même était sain, y compris sur les deux rendus les plus
susceptibles de le casser : un jour à un chiffre, qu'openssl écrit avec un double
espace (`Sep  1`), et un notAfter au-delà de 2050, où l'encodage ASN.1 passe de
UTCTime à GeneralizedTime. Les deux sont désormais verrouillés.

### « curl | sudo bash » n'était pas détecté, et « curl | ssh host » l'était

La règle « un téléchargement redirigé directement dans un shell » existait en
deux exemplaires, deux expressions régulières en désaccord entre elles et avec
la réalité :

    cron_audit       \b(curl|wget)\b.*\|\s*\S*sh\b
    systemd_timers   \|\s*(/[a-z/]*/)?(?:ba)?sh\b

La première acceptait **tout token finissant par « sh »** : `curl … | ssh
backup@host` — un pipe ordinaire vers une machine distante — était donc signalé
comme risque de chaîne d'approvisionnement. Elle exigeait aussi que le token
suivant immédiatement le pipe *soit* le shell, si bien que `curl … | sudo bash`
passait entièrement au travers : la forme la plus publiée de ce one-liner, et la
dangereuse, puisqu'elle exécute le script téléchargé en root. `| sudo -E bash`,
`| env bash`, `| nohup sh` et `| timeout 60 bash` subissaient le même sort.

La seconde ne connaissait que `sh` et `bash` : `| zsh` passait inaperçu dans les
timers alors que cron_audit le voyait. Une règle, deux implémentations, deux
angles morts différents — la troisième occurrence de cette forme dans ce cycle,
après le commentaire de fin de ligne et le glyphe d'état systemd.

`pipes_into_shell` vit désormais dans `bob/checks/_run.py` et compare le mot de
commande de chaque étape du pipe au lieu d'un suffixe : il enjambe un wrapper
`sudo` / `env` / `nice` / `timeout` ainsi que ce qui appartient à ce wrapper,
retire la ponctuation shell qu'un fichier d'unité laisse sur le dernier token
(`ExecStart=/bin/bash -c "curl … | bash"`), et examine les étapes suivantes pour
attraper `curl … | tee /tmp/x | sh`.

Une imprécision assumée, conservée : le téléchargeur est cherché n'importe où
avant le premier pipe, donc l'artificiel `echo curl | sh` est signalé. Cela
penche vers la détection, direction que le reste de l'outil adopte déjà, et le
finding cite la ligne : l'opérateur le voit immédiatement.

### `ufw allow OpenSSH` laissait le port 22 paraître sans protection

`ufw status numbered` était analysé par une seule expression régulière qui
lisait le premier nombre de la colonne « To » et s'arrêtait là. Trois formes de
règles ordinaires la mettaient en défaut, toutes confirmées contre le source
d'ufw lui-même (`backend_iptables.get_status`) et ses profils livrés dans
`/etc/ufw/applications.d`.

**Profils d'application.** En mode non verbeux — celui que BOB lit — ufw
affiche le *nom* du profil dans la colonne « To » et aucun port. `ufw allow
OpenSSH` est précisément ce que la documentation d'Ubuntu demande de taper :
une machine qui suivait les instructions s'entendait donc dire que son port SSH
n'avait aucune règle de pare-feu. Samba, CUPS et Postfix subissaient le même
sort.

**Plages.** `6000:6007/tcp` ne faisait correspondre que « 6000 », et perdait le
protocole au passage : 6001-6007 étaient lus comme non couverts *et* 6000/udp
comme couvert — une seule règle, fausse dans les deux sens à la fois.

**Listes.** `80,443/tcp` se comportait de même : 443 non couvert, 80/udp
couvert.

La couverture est désormais une liste de plages `(bas, haut, proto)` plutôt
qu'un ensemble de ports exacts : une règle peut légitimement couvrir toute la
plage éphémère, et une plage ne peut pas servir de clé d'ensemble sans être
développée. La table des profils est collectée dans `from_system` et non lue
dans le contrôle : `check_xxx` est pur par contrat, et un correctif qui glisserait
discrètement des entrées-sorties dans une fonction pure échangerait un défaut
contre un pire.

Vérifié sur le vrai `/etc/ufw/applications.d` de cette machine, y compris la
double spécification de Samba `137,138/udp|139,445/tcp` et les noms de profils
contenant des espaces.

### Un état seccomp illisible était indiscernable d'un seccomp actif

L'essentiel de `container_security` a été confronté à podman et s'accordait sur
toutes les configurations qu'on peut lui demander — `--privileged`,
`--cap-add SYS_ADMIN`, `--cap-drop=ALL`, `--read-only`,
`--security-opt no-new-privileges`, `--userns=keep-id`, ainsi que la détection
dans une image dépourvue de `systemd-detect-virt`. La passe de v0.14.1 sur ce
fichier a fait son travail, et la sémantique `privileged` qu'elle a introduite
tient face à un vrai conteneur privilégié (ensemble de bornage 2199023255551)
contre un octroi ciblé (2149844475).

Un manque y a survécu. `snapshot.seccomp` vaut -1 quand `/proc/self/status` ne
comportait pas de ligne `Seccomp`, et le contrôle ne testait que `== 0` : -1
passait donc en silence. La section conteneur ne disait rien de seccomp, ce que
l'opérateur lit comme « seccomp est en place ».

Or le noyau n'émet cette ligne que sous `CONFIG_SECCOMP`. Elle manque donc
précisément sur un noyau sans aucun support seccomp : le cas où la remarque
compte le plus était celui qui n'en produisait aucune. « Inconnu » est désormais
une réponse à part entière, qui nomme la raison et la commande de vérification
au lieu d'emprunter le silence réservé à un filtre actif.

Même forme que les lecteurs sysctl plus tôt dans ce cycle — « n'a pas pu lire »
et « tout va bien » aboutissant à la même sortie — dans le troisième module à la
présenter.

### Une pile IPv6 absente était lue comme active, et déclarée conforme

Ce module avait été examiné plus tôt dans le même cycle et laissé passer sur le
raisonnement qu'un défaut optimiste penche vers l'alarme : supposer IPv6 actif,
et le contrôle cherchera ensuite les règles de pare-feu IPv6 manquantes pour
avertir. L'exécuter au lieu de raisonner dessus a montré l'inverse. Les deux
lectures échouant et sans écouteur IPv6, la sortie est `[OK] ipv6.config_ok` —
une affirmation explicite que la configuration IPv6 est cohérente, à propos
d'une pile que BOB n'a pas pu lire du tout.

`/proc/sys/net/ipv6` est créé quand la pile IPv6 enregistre ses sysctls :
démarrer avec `ipv6.disable=1` — ou un noyau compilé sans IPv6 — laisse donc
l'arbre entier absent. Le fichier manquait *parce qu'*IPv6 était éteint, et
`except OSError: return True  # assume enabled if unreadable` en concluait qu'il
était allumé. Le déclencheur exact que le correctif `hardening` de ce cycle
avait déjà nommé, dans un module écarté par argument plutôt que par mesure.

Un arbre absent est désormais traité pour ce qu'il est : une réponse. Vérifié
sous namespace de montage avec `/proc/sys/net` remplacé par un tmpfs vide, où le
lecteur renvoie maintenant « éteint, et on le sait ». Une lecture qui échoue pour
toute autre raison reste inconnue et obtient son propre INFO, le verdict
environnant restant calculé sur la lecture prudente plutôt que supprimé.

La leçon est consignée parce qu'elle a coûté un défaut : un module écarté par
raisonnement n'est pas un module écarté.

### Un durcissement de umask ajouté en fin de fichier n'était pas vu

Le même défaut que `password_policy`, dans un module que le premier balayage
n'avait pas atteint. Tous les fichiers que lit `_scan` retiennent la dernière
valeur, et il prenait la première.

Mesuré plutôt que déduit. `/etc/login.defs` : le `useradd --prefix` de shadow
lui-même, sur un fichier contenant UMASK deux fois, crée le répertoire personnel
en **700** pour `022` puis `077`, et en **755** pour `077` puis `022` — c'est la
dernière ligne que shadow applique, dans les deux ordres. `/etc/profile` :
sourcer un fichier contenant `umask 022` puis `umask 027` laisse `0027`, ce qui
est simplement la façon dont un shell lit un script.

L'opérateur qui durcit de la manière ordinaire — en ajoutant la valeur plus
stricte à la fin — s'entendait donc dire que la valeur d'origine de la distro
était toujours en vigueur. Et l'inverse, qui est la direction qui compte : un
umask strict affaibli par une ligne ajoutée était rapporté comme le strict qu'il
avait remplacé.

### Toutes les connexions établies étaient perdues, et un contrôle avec elles

Le pire constat du cycle, et ce n'était pas un verdict faux — c'était un
contrôle qui ne pouvait pas s'exécuter du tout.

`NetworkContextSnapshot` lance `ss -tnp state established`. Avec un filtre
d'état, ss connaît déjà l'état et **supprime la colonne State** :

    Recv-Q Send-Q  Local Address:Port   Peer Address:Port  Process
    0      0       192.168.1.10:56692   104.18.39.21:443   users:(("brave",…

L'analyseur lisait « Local » à l'index fixe 3 — qui est le *pair* — et le pair à
l'index 4, qui est la colonne processus. `_split_addr_port` rejette
`users:(("brave",…))` : la ligne était donc ignorée. Toutes les lignes, toujours.
Mesuré sur la machine de développement : **ss annonçait 32 connexions établies et
le snapshot en rapportait 0**.

`network_context` signale une connexion établie vers une IP externe sur un port
sensible, avec 2 points de déduction. Il parcourt cette liste vide : il ne
pouvait jamais se déclencher. Le `connections_count` du JSON, la liste des IP
distantes les plus fréquentes et l'affichage de synthèse étaient mis à zéro par
la même cause — une section qui n'affichait rien et ressemblait à une machine
tranquille.

Les deux dispositions sont désormais distinguées par la seule chose qui les
sépare sans deviner : un mot-clé d'état n'est jamais numérique et Recv-Q l'est
toujours. La forme avec State — `ss -tn`, et l'exemple de la docstring de la
fonction elle-même — continue de fonctionner, et est verrouillée.

La garde qui aurait attrapé cela dès le premier jour est maintenant dans le
fichier : analyser la sortie `ss` réelle et la comparer ligne à ligne aux
colonnes qu'ss a imprimées.

### Une requête refusée était rapportée comme « rien de configuré », avec déduction

`auditd` et `fail2ban` demandent tous deux sa configuration à un outil, et lisent
tous deux une réponse vide comme une configuration vide. `_run` jette le code de
retour : un appel échoué et un résultat réellement vide sont la même chaîne.

Mesuré sur la machine de développement, les deux services tournant :

    auditctl -l             ->  code 4,   stdout vide
    fail2ban-client status  ->  code 255, stdout vide

Chacun produisait un WARN et une déduction d'un point pour une configuration que
BOB n'avait jamais lue — et `auditd` déduisait un *second* point pour des
surveillances de fichiers sensibles absentes, dérivées de la même sortie vide. La
direction est la prudente, ce qui explique sa survie à toutes les passes
précédentes, mais cela reste une affirmation fausse assortie d'un score :
exactement le genre que l'opérateur réfute en une commande, et c'est ainsi que les
constats voisins perdent leur crédit.

Aucune plomberie de code de retour n'a été nécessaire, chaque outil fournissant
son propre discriminateur :

* `auditctl` affiche littéralement `No rules` quand le système d'audit est
  joignable et n'en contient aucune — la chaîne est dans le binaire. Une sortie
  vide signifie donc que la requête a échoué.
* `fail2ban-client status` émet toujours une ligne `Jail list:`, vide ou non
  (`fail2ban/client/beautifier.py`).

Les deux signalent désormais l'échec en INFO, en nommant la commande à lancer à
la main, et ne déduisent rien.

### Deux protections de plus rapportées absentes faute d'avoir pu être lues

Toutes deux trouvées en élargissant le balayage auditd/fail2ban, et toutes deux
démontrables sur la machine de développement plutôt qu'hypothétiques.

**AppArmor.** `aa-status` réussit *partiellement* sans le privilège de lire le
jeu de profils : il imprime `apparmor module is loaded.` sur stdout, puis sort en
code 4 avec l'explication sur stderr. BOB lisait la ligne du module — à juste
titre — et extrayait les compteurs de profils de cette même sortie tronquée,
obtenant 0. Cette machine porte **120 profils en mode enforce** et s'entendait
dire qu'elle n'en avait aucun, avec un WARN et un point. Un jeu de profils
joignable produit toujours une ligne de comptage (`%zd profiles are loaded.` est
dans le binaire) : son absence est le discriminateur.

Ce module avait été examiné plus tôt dans le cycle et écarté, au motif que ses
chaînes de format correspondaient et que ses tests passaient. La même erreur que
pour `ipv6`, une deuxième fois : **vérifier que l'analyseur est juste n'est pas
vérifier que le verdict l'est**.

**Jeu de règles du pare-feu.** `iptables -S` écrit « Permission denied (you must
be root) » sur stderr et laisse stdout vide : le snapshot retombait donc sur
`backend="none"` — `firewall_iptables.no_backend`, un WARN assorti d'une
déduction de **3 points**, la plus lourde du contrôle. Un `iptables -S` qui
fonctionne imprime toujours ses lignes de politique, même sur une machine sans
aucune règle : un résultat vide venant d'un binaire installé signifie donc que la
requête a été refusée. `nft list ruleset` n'imprime rien pour un jeu de règles
réellement vide et ne peut donc pas distinguer les deux seul ; iptables le peut,
et il est présent sur pratiquement toutes les machines visées par BOB, y compris
comme couche de compatibilité au-dessus de nft.

Ni un mauvais seuil ni un mauvais motif. Dans les deux cas, une lecture partielle
ou refusée présentée comme complète.

### Une adresse source faisait passer des ports sans rapport pour protégés

`services._classify_exposure` cherchait le numéro de port sur toute la ligne de
`ufw status numbered`. Une règle ordinaire :

    [ 1] 80/tcp   ALLOW IN   192.168.1.22

correspondait donc aux ports 1, 22, 168 et 192 autant qu'au 80, et chacun était
rapporté OPEN_LOCAL — « ouvert, restreint au réseau local ». Le port 22 est le
pire cas et le plus probable, étant le dernier octet le plus courant sur un
réseau RFC1918 : une machine faisant tourner SSH **sans aucune règle de
pare-feu** s'entendait dire que SSH était restreint au LAN. Faussement rassurant,
sur le contrôle qui couvre 38 services.

`ports.py` avait raison sur ce point, et disait pourquoi dans une docstring —
« pour éviter de faire correspondre des numéros de port apparaissant plus loin
sur la ligne, par exemple dans des IP sources comme 192.168.1.22 ». Deux
implémentations d'une règle, une seule correcte : la quatrième occurrence de
cette forme dans le cycle, après le commentaire de fin de ligne, le glyphe d'état
systemd et le détecteur de pipe-to-shell.

La grammaire vit désormais dans `bob/checks/_ufw.py` et les deux appelants s'en
servent : `services` gagne donc aussi ce que `ports` avait appris plus tôt dans
le cycle — profils d'application (`ufw allow OpenSSH`), plages
(`6000:6007/tcp`) et listes (`80,443/tcp`). La restriction de source est lue dans
la seule colonne From : la lire sur toute la ligne faisait passer une
*destination* privée pour une source privée.

Deux mutations ont dû être rejouées ici. La première a survécu, et à juste titre :
le test censé verrouiller « une destination privée n'est pas une source privée »
utilisait une règle que l'analyseur ne reconnaissait pas du tout, et passait donc
sans rien tester — ce qui a révélé un vrai manque, puisque
`ufw allow from any to 192.168.1.5 port 22` imprime la destination devant le port
et ne correspondait à rien.

### Un JSON valide mais non-objet faisait planter les contrôles Docker

`/etc/docker/daemon.json` était lu par `json.loads` puis utilisé comme
dictionnaire, en ne capturant que `json.JSONDecodeError`. Or `[]`, `"texte"`,
`null`, `42` et `true` sont tous du JSON valide et aucun ne possède `.get()` :
chacun faisait donc remonter une `AttributeError` hors de
`DockerSnapshot.from_system()` et de `docker_audit._read_userns_remap()`.

Depuis la barrière de cœur de v0.15.0, cela ne tue plus l'audit — la section
Docker est dégradée — mais la section est tout de même perdue, et le moment où un
opérateur lance un audit est précisément celui où daemon.json est cassé, puisque
Docker refuse de démarrer sur un tel fichier. Les deux lecteurs traitent
désormais un non-objet comme illisible, au même titre qu'un JSON malformé.

La distinction qui compte est verrouillée : un fichier lisible contenant
`{"iptables": false}` signale toujours que Docker contourne le pare-feu, et la
chaîne `"false"` toujours pas, puisque Docker n'honore que le booléen.

### Deux résultats négatifs du même tour, consignés plutôt que traités

**Le registre des services.** Les 38 entrées ont été croisées avec
`/etc/services`, le registre de ports du système lui-même : **zéro divergence**
sur 50 ports déclarés. Aucun identifiant dupliqué, aucune spécification de port
invalide, un vocabulaire `risk` fermé. Les ports partagés entre entrées (80/443
pour apache, nginx, nextcloud et caddy) sont corrects — un seul d'entre eux est
installé à la fois.

Quatre entrées — postgresql, avahi, plex, syncthing — n'ont pas de bloc
`detection` optionnel : elles sont donc trouvées par dpkg seul là où les 34
autres cherchent aussi un binaire ou un fichier de configuration. C'est la forme
familière, un invariant tenu par 34 entrées sur 38, et il est délibérément laissé
tel quel : le compléter reviendrait à écrire des chemins d'installation pour
trois paquets absents de toute machine disponible ici, c'est-à-dire à deviner —
ce que ce cycle s'interdit. Consigné pour que le prochain lecteur voie une
décision et non un oubli.

**daemon.json illisible.** `_check_daemon_json` renvoie « iptables non
désactivé » quand le fichier existe mais n'est pas lisible — la forme faussement
rassurante corrigée ailleurs dans ce cycle. Elle est laissée en l'état : le
fichier est en 0644 par défaut et BOB s'exécute en root, donc contrairement à
`auditctl -l` ou `aa-status`, il n'existe pas de mode de défaillance qu'on puisse
démontrer plutôt qu'imaginer.

### Le rapport Markdown rendait ce que la machine auditée mettait dans un nom

Les messages de findings portent des valeurs venues du système — noms de
processus, commandes cron, chemins de fichiers, noms de services et de prisons.
`_md_escape` échappait `|` pour ne pas casser le tableau, et s'arrêtait là. Or
une cellule Markdown rend le HTML en ligne, les liens et les images : tout le
reste passait intact.

```text
<img src=x onerror=alert(1)>      s'exécute dans tout rendu qui laisse passer le HTML
[click](javascript:alert(1))      rendu comme un lien actif
![x](https://evil.invalid/t.png)  télécharge une image distante à l'ouverture
```

La dernière est la plus intéressante : elle fait sortir une requête depuis la
machine de **l'auditeur** vers un hôte choisi par l'attaquant, à cause d'une
chaîne présente sur la machine **auditée**, au moment où l'opérateur ouvre son
propre rapport.

L'écrivain HTML échappait tout cela depuis toujours, et `report_markdown.py` —
le rapport détaillé `-d` — avait été durci en v0.7.3 avec un `_safe_url`
documenté après un XSS trouvé à l'époque. `markdown_output.py` était le
troisième écrivain, et le seul restant. Le même invariant, tenu par deux formats
de sortie sur trois : cinquième occurrence de cette forme dans le cycle.

`cmd` n'est **délibérément pas** échappé en entités. Il est rendu dans un code
span, où Markdown traite le contenu littéralement, et `&lt;` y afficherait cinq
caractères là où une commande destinée à être copiée comporte un `<`. Ce dont un
code span a besoin, c'est d'une clôture plus longue que la plus longue suite de
backticks qu'il contient, plus un espace de remplissage si le contenu commence ou
finit par un backtick (CommonMark 6.3) — ce que fait le nouveau `_md_code`, et ce
que l'ancien encadrement par un seul backtick ratait.

### Surfaces hors checks/, examinées et saines

Le moteur de score, son détail, l'écrivain JSON et la comparaison de baseline ont
tous été croisés, et aucun n'a bougé :

* **Niveaux de risque** — chaque score de -1 à 11 confronté à son niveau ; les
  seuils à 3/5/8 sont monotones, sans décalage d'une unité.
* **Arithmétique du détail** — sur un audit réel, les déductions somment
  exactement à `MAX_SCORE - score`, chacune porte un motif et une clé, et chacune
  correspond à un finding. Quand les déductions dépassent le maximum, l'affichage
  le dit en toutes lettres — « Raw score (sum of deductions): -8/10 » au-dessus
  de « Final score: 0/10 » — au lieu de présenter en silence une arithmétique qui
  ne tombe pas juste.
* **Sortie JSON** — score, nombre de findings, compteurs d'alertes et
  d'avertissements, sections dégradées, profil et nombre de déductions
  correspondent exactement au moteur ; le document fait l'aller-retour par
  `json.dumps`/`loads` ; aucune clé de finding n'est perdue.
* **Comparaison de baseline** — `save` puis `load` rend un objet identique, une
  baseline comparée à elle-même n'annonce aucun changement, et le fichier est
  écrit en 0600.

### Une chaîne sur la machine auditée pouvait pinger tout un espace Slack

`build_slack_payload` envoyait les messages de findings verbatim, et l'analyseur
mrkdwn de Slack interprète deux constructions qui comptent ici :

```text
<!channel>                            notifie tout le monde dans le canal
<http://ailleurs|paraît légitime>     un lien dont le texte visible est sous le
                                      même contrôle que la destination
```

Les messages de findings portent des valeurs venues du système : un nom de
processus, une commande cron ou un nom de service sur la machine auditée
arrivait donc dans le canal de sécurité avec la main sur son propre rendu. Les
règles de formatage de Slack exigent que `&`, `<` et `>` soient envoyés
échappés ; BOB ne le faisait pas.

Même famille que le rapport Markdown corrigé en parallèle — du contenu venu de
la machine auditée arrivant là où du balisage est rendu — et sixième occurrence
dans ce cycle d'un invariant tenu par certains chemins de sortie et pas par
d'autres.

La charge générique (non-Slack) n'a délibérément pas d'équivalent : elle est
consommée comme du JSON, pas comme du balisage, et y échapper corromprait les
valeurs que lit le consommateur. Un test verrouille cette distinction pour que
les deux ne dérivent pas l'une vers l'autre.

### Deux surfaces de plus, examinées et saines

* **Appariement `--ignore`.** Correspondance exacte de clé, plus une seule
  correspondance héritée documentée (`ssh.x11_forwarding` →
  `ssh.x11.forwarding.*`). Testé contre le sur-appariement dans neuf directions,
  dont un `*` nu et un `ssh.*` écrits dans `ignore.yml` : ni l'un ni l'autre ne
  correspond à quoi que ce soit, donc un opérateur ne peut pas réduire l'audit
  au silence par accident.
* **Transport du webhook.** Aucun contexte TLS non vérifié dans l'arbre ;
  `urlopen` valide donc les certificats par défaut. `redact_url_credentials`
  traite les formes `user:pass@`, `user@` et `:token@` et laisse intacte une URL
  sans identifiants.

### Six surfaces de plus, toutes saines

Le balayage a atteint la fin du code hors `checks/`. Rien n'a bougé, et cela
mérite d'être écrit avec autant de précision qu'un défaut — une surface consignée
comme examinée est une surface que le prochain audit peut sauter.

* **Comptage de récurrence.** Une clé présente dans des audits consécutifs
  s'incrémente ; une clé qui disparaît perd son compteur ; une clé qui revient
  repart à 1. Éprouvé sur cinq audits successifs avec un finding corrigé puis
  réapparu — le compteur ne se reporte pas, donc un problème qui revient n'est
  pas annoncé comme ancien.
* **Historique de score.** Aller-retour par `history.jsonl` ; fichier écrit en
  0600 ; la rotation au-delà de 1000 entrées garde les mille *plus récentes* ;
  une ligne corrompue est sautée au lieu de tuer la lecture ; les scores hors
  bornes ou non numériques sont ramenés dans [0, 10].
* **`--explain`.** Les 11 clés WARN/ALERT émises sur la machine de test ont une
  entrée. Chaque clé ajoutée dans ce cycle est INFO : aucune n'a créé de dette
  d'explication. Une clé inconnue sort en code 3 et la correspondance approchée
  suggère juste — `ssh.root_logni` renvoie `ssh.permit_root_login`. Une
  traversée de chemin ou un glob sont traités comme des clés inconnues
  ordinaires.
* **Sortie terminal.** Revérifiée contre l'injection ANSI avec cinq charges : un
  hyperlien OSC 8, une remise à zéro de couleur tentant de peindre un faux OK
  vert, un retour chariot tentant d'écraser la ligne, un effacement d'écran et un
  changement de titre de terminal. Tout octet ESC est retiré : chacune s'affiche
  en texte littéral inerte.
* **Validation CLI.** Neuf invocations malformées — valeurs manquantes,
  `--check`/`--skip` en conflit, `--output` invalide, traversée dans `--lang`,
  `--log-days` négatif, `--json-v1` retiré, drapeaux de sortie combinés —
  produisent toutes un message spécifique et sortent en 3, le 0 restant réservé
  aux chemins informatifs.
* **Appariement `ignore.yml`** et **transport du webhook**, consignés dans
  l'entrée précédente.

Deux artefacts de harnais ont été traqués avant de pouvoir être rapportés comme
des découvertes : un code de retour 0 qui était celui de `head` et non de BOB, et
une « charge non sérialisable » qui venait d'un argument passé dans le mauvais
paramètre. Ils sont notés parce que la discipline qui les attrape est celle qui
rend les vraies découvertes dignes de confiance.

## Ce qui change pour un consommateur

Tout dans cette version est additif ou correctif. Aucune clé n'a été renommée ni
retirée, aucune version de schéma n'a changé, aucun code de retour n'a bougé.

### Quatorze nouvelles clés de findings

Neuf signalent un état que BOB ne savait pas distinguer d'un verdict — « je n'ai
pas pu lire » au lieu de « tout va bien » ou « c'est cassé ». Les neuf sont en
INFO et ne portent aucune déduction : un score ne peut pas bouger à cause d'elles.

| Clé | Émise quand |
|-----|-------------|
| `auditd.rules_unreadable` | `auditctl -l` n'a rien renvoyé alors qu'auditd tourne |
| `fail2ban.status_unreadable` | `fail2ban-client status` n'a renvoyé aucune liste de prisons |
| `mac_policy.apparmor_profiles_unreadable` | `aa-status` a signalé le module mais pas le jeu de profils |
| `firewall_iptables.ruleset_unreadable` | un binaire backend existe mais son jeu de règles est illisible |
| `container_security.seccomp_unknown` | `/proc/self/status` ne comportait pas de ligne `Seccomp` |
| `ipv6.kernel_state_unknown` | `/proc/sys/net/ipv6` existe mais n'a pas pu être lu |
| `hardening.params_unavailable` | un ou plusieurs sysctls réseau ne sont pas exposés par ce noyau |
| `kernel_hardening.params_unavailable` | idem, pour les cinq réglages de durcissement noyau |
| `user_accounts.ambiguous_expiry` | le champ d'expiration d'un compte vaut `0`, que `shadow(5)` déclare ambigu |

Cinq autres sont des findings qui existaient depuis toujours et n'avaient
**aucune clé** : ils étaient inatteignables par `--explain`, non supprimables par
`--ignore`, non suivis par la récurrence, et parvenaient anonymes à la sortie
JSON — `ddns.none`, `ddns.no_open_ports`, `logs.no_logfile`,
`logs.source_journald`, `logs.empty`.

### Quatre changements de sortie

* **JSON `hardening.*`** — un paramètre que le noyau n'expose pas vaut désormais
  `null` au lieu d'un booléen fabriqué. Un test de véracité côté consommateur lit
  `null` exactement comme il lisait le `false` inventé ; seule une comparaison
  `is False` voit une différence, et seulement là où l'ancienne valeur était
  inventée.
* **JSON `ports[].address`** — une adresse IPv6 ne porte plus son suffixe
  `%scope` ; la portée passe dans le champ `iface`, là où le chemin IPv4 l'a
  toujours mise.
* **`ssl_certs`** — un certificat dans ses dernières 24 heures rapporte désormais
  `ssl_certs.expiring_critical` au lieu de `ssl_certs.expired`. Cela reste une
  ALERTE avec la même déduction ; seule l'affirmation change, parce que le
  certificat est encore valide.
* **Sorties Markdown et Slack** — le texte des findings est désormais échappé
  pour le format dans lequel il est écrit. Un message contenant `<`, `[` ou `&`
  s'affiche comme ces caractères au lieu d'être interprété comme du balisage.

### Deux comportements qui ne coûtent plus rien

`auditd.no_rules` et `fail2ban.no_jails` ne se déclenchent plus quand la requête a
échoué, et `firewall_iptables.no_backend` ne se déclenche plus quand le jeu de
règles était simplement illisible. Une machine qui perdait jusqu'à cinq points
sur ces trois-là peut donc obtenir un meilleur score après mise à jour — non
parce qu'elle a changé, mais parce que BOB a cessé de déduire pour une
configuration qu'il n'avait jamais lue.

### Routine de documentation

À partir de ce cycle, les compteurs du SNAPSHOT sont rafraîchis **au fil de la branche**, et non au moment de la
publication, et les fichiers de surface de version sont ouverts à l'ouverture de la branche. Les gardes doc
existantes travaillent alors *pendant* le développement au lieu de ne servir qu'au tag.

**Tests** 6719 → **7220**.

---

## [v0.14.1] — 30-08-2026

**Patch d'exactitude. La surface conteneur est INFO-only : aucun changement de score, de champ de sortie ni de code de retour ; une clé de finding additive.**

### « Privilégié » signifiait « CAP_SYS_ADMIN est présente »

`bob/checks/container_security.py` calculait :

```python
snap.privileged = bool(snap.cap_bnd & (1 << _CAP_SYS_ADMIN_BIT))
```

Un conteneur lancé avec `--cap-add SYS_ADMIN` — un octroi ciblé, courant pour les montages FUSE ou les conteneurs imbriqués, avec seccomp toujours actif — était donc rapporté **PRIVILÉGIÉ**, sous ce titre :

> Le conteneur semble PRIVILÉGIÉ — jeu complet de capabilities Linux disponible

Mesuré sur de vrais conteneurs podman (`cap_last_cap = 40`, le jeu complet vaut donc `(1 << 41) - 1`) :

```
défaut rootless       cap_bnd 2147747323     seccomp 2   privileged False
--privileged          cap_bnd 2199023255551  seccomp 0   privileged True
--cap-add SYS_ADMIN   cap_bnd 2149844475     seccomp 2   privileged True   <-- affirmation fausse
```

La ligne de détail était déjà prudente — *« Un conteneur privilégié (ou doté de CAP_SYS_ADMIN) »*. Seul le titre mentait, et c'est le titre que l'opérateur lit en premier.

**Le correctif.** `privileged` signifie désormais le bounding set **complet**, dérivé de `/proc/sys/kernel/cap_last_cap` plutôt que d'une constante en dur — le fichier est lisible dans les conteneurs aussi, et le lecteur est borné, parce qu'une valeur aberrante décalerait le masque au point de faire passer tout conteneur pour non privilégié. Une CAP_SYS_ADMIN isolée obtient son propre finding, la nouvelle clé additive `container_security.cap_sys_admin`, qui énonce clairement que le conteneur n'est *pas* privilégié mais détient la capability sur laquelle reposent la plupart des évasions documentées. Les deux messages sont réécrits en EN et FR.

**Pourquoi cela dépasse la formulation.** La déduction conteneur prévue pour v0.15.0 devait être keyée sur `privileged`. La livrer contre l'ancienne sémantique aurait pénalisé un conteneur à portée FUSE exactement autant qu'un conteneur pleinement privilégié — et le backlog liste `privileged` et `CAP_SYS_ADMIN` comme conditions *distinctes*, que le code avait silencieusement fusionnées.

**Pourquoi cela a survécu.** Les tests existants posaient `privileged=True` ou `privileged=False` directement sur le snapshot, sans jamais dériver le champ d'un bounding set réaliste ; `test_privileged_bit_detection` vérifiait le bit, jamais la sémantique. Rien n'exerçait le cas CAP_SYS_ADMIN seule.

Le piège se retend facilement : la **première version des nouveaux gardes réimplémentait la logique de masque à l'intérieur du test**, et passait tranquillement quand l'ancienne ligne buguée était restaurée. Ils ont été réécrits pour piloter le vrai `from_system()` avec les masques mesurés sur podman, et sont désormais mutation-testés deux fois — revenir à l'ancienne classification en fait échouer deux, retirer la nouvelle branche d'émission en fait échouer deux autres.

### La date de release de v0.14.0 était fausse

Les surfaces de release ont été figées au 2026-08-28 au démarrage du travail, mais le push et la publication PyPI ont eu lieu le lendemain : le workflow qui a uploadé 0.14.0 est horodaté `2026-08-29T16:46:08Z`.

Corrigé sur les seules surfaces v0.14.0 — la ligne de changelog et l'en-tête de section, les entrées debian et rpm de `0.14.0-1`, les trois lignes `.TH` des pages de man, l'en-tête du SNAPSHOT et sa ligne « release surface dated », et la date de fin de vie de v0.13.x dans `SECURITY{,_FR}.md` (qui est par définition le jour du ship de v0.14.0). Le jour de la semaine suit : le 2026-08-29 est un samedi, et le garde de jours de semaine ajouté en v0.14.0 le confirme.

**v0.13.3 et v0.13.4 gardent leurs dates au 2026-08-28** — elles ont réellement été publiées ce jour-là, leurs workflows horodatés 17:31 et 18:00 UTC le 28. Seule v0.14.0 a franchi minuit.

### Un lot robustesse, issu d'une campagne de stress test locale

Le travail v0.14.1 a été suivi d'une passe de stress délibérée contre l'outil : 1 209 combinaisons d'argv hostiles, fichiers d'état corrompus soumis à chaque parser, balayage de tous les checks sous user namespace restreint, 8 exécutions concurrentes, tube rompu, stdout fermé, attaques par lien symbolique et par encodage. Sept défauts en sont sortis. Trois coûtaient à l'opérateur l'audit entier.

#### 1. Un seul check en échec détruisait tout l'audit

`runner._sec` — le helper qui distribue ~34 des sections de l'audit — n'avait aucune gestion d'exception :

```python
result = check_fn(snapshot, t=t, **check_kwargs)
engine.apply(result)
display_result(...)
```

Toute exception levée par un collecteur de snapshot ou une fonction de check remontait hors de `run_checks` jusqu'au handler global de `bob/__main__.py`. L'opérateur obtenait **exit 3 et zéro octet sur stdout** — pas de score, pas de findings, pas de rapport — parce qu'une section n'avait pas pu lire un fichier.

Reproduit en live, avec une fixture bind-montée sur `/etc/passwd` dans un user namespace :

```
$ sudo bob --format=json
EXIT=3 stdout=0B
Fatal error: 'utf-8' codec can't decode byte 0xe9 in position 3278: invalid continuation byte
```

Le déclencheur était un unique octet latin-1 dans un champ GECOS — `José García` — ce qui est banal sur les systèmes antérieurs au défaut UTF-8.

**Le correctif.** Une section en échec est dégradée sur place. L'audit va au bout, l'échec est émis par le chemin normal `engine.apply` sous forme d'un finding INFO `<section>.unavailable` — il atteint donc le texte, JSON, CSV, Markdown, HTML et le rapport `-d` — et le nom de la section est consigné dans `ChecksResult.degraded_sections`, exposé comme nouveau champ JSON de premier niveau :

```
EXIT=2 stdout=2344B
score: 8 | alert: 1 warn: 5 info: 67
degraded_sections: ['user_accounts']
```

`degraded_sections` est **additif dans le schéma v3** (sans bump — le même traitement que les champs ajoutés en v0.12.1). Il existe pour qu'un pipeline distingue « score 9, toutes sections évaluées » de « score 9, deux sections jamais exécutées » sans parser les findings.

**Les codes de sortie sont délibérément inchangés.** Router une section dégradée vers `EXIT_ERROR` a été envisagé puis écarté : cela entrerait en collision avec l'exit 4 de `--target` — rendant à nouveau inatteignable le contrat de cible documenté, ce que v0.14.0 venait précisément de réparer — et détruirait la distinction existante entre « BOB est cassé » (rien n'a tourné) et « un fichier était illisible » (un audit a été produit). Le coût accepté est qu'un cron ne lisant que le code de sortie pourrait voir 0 alors qu'une section n'a pas tourné ; c'est pourquoi la dégradation est bruyante dans tous les formats rendus et détectable par machine dans le JSON.

**La barrière était inerte à sa première écriture.** 29 des 34 sites d'appel de `_sec` collectaient leur snapshot *une ligne au-dessus* de l'appel :

```python
user_accounts_snapshot = UserAccountsSnapshot.from_system()   # ← la lecture se fait ici
_sec("user_accounts", user_accounts_snapshot, check_user_accounts)
```

La collecte de snapshot est précisément l'endroit où se font les lectures de fichiers — et donc les crashes — si bien qu'entourer la seule fonction de check ne protégeait rien. Le premier re-test renvoyait toujours exit 3. Convertir ces 29 sites en fabriques paresseuses était un prérequis pour que la barrière ait un sens, et livre au passage le gain de performance lazy-snapshot différé depuis v0.13.3 : `--check=ssh` ne paie plus 29 snapshots qu'il n'utilisera pas — mesuré sur cet hôte, en alternant ancien/nouveau trois fois, **2,60 s → 1,91 s (−27 %)**. `hardening_snapshot` reste impatient et est documenté comme l'exception — il alimente aussi `ChecksResult` pour le bloc sysctl de `--json-full`.

**Périmètre délibérément borné.** Le noyau always-on (`firewall`, `firewall_rules`, `ufw_logging`, `firewall_iptables`, `firewall_drivers`, `network_context`, `services`, `ports`, `logs`, `ddns`, `docker`, `virtualization`) n'est **pas** protégé. C'est un pipeline de données, pas un ensemble de sections indépendantes : `fw_status`, `ports_snapshot`, `ufw_numbered`, `network_context` et `audited_ports` circulent entre elles puis vers les appels `_sec`. Y avaler une erreur laisserait le code aval lire des noms jamais liés — une cascade de `NameError`, strictement pire que l'abandon actuel. Si le noyau pare-feu est illisible, il n'y a génuinement pas d'audit à rendre.

#### 2. Un octet non-UTF-8 échappait à 33 gardes `except OSError`

`UnicodeDecodeError` est une sous-classe de `ValueError`, pas d'`OSError` : elle traversait donc sans encombre tout garde de la forme :

```python
try:
    text = path.read_text(encoding="utf-8")
except OSError:
    ...
```

Deux reproductions en live. Le champ GECOS d'`/etc/passwd` ci-dessus — et, pire, un commentaire accentué dans `~/.config/bob/ignore.yml` écrit avec un éditeur latin-1, qui **briquait toutes les exécutions suivantes** de cet utilisateur :

```
$ bob --format=json --check=ssh
EXIT=3
Fatal error: 'utf-8' codec can't decode byte 0xe8 in position 3: invalid continuation byte
```

Un opérateur francophone écrivant `# règle ignorée` dans le mauvais encodage désactivait définitivement son propre auditeur, et l'erreur rendue était un message de codec Python non traduit.

Toute lecture de texte sous garde déclare désormais `errors="replace"`. Un garde AST balaie l'ensemble du paquet et échoue si un `read_text()` sans politique `errors=` réapparaît un jour dans un `try` ne capturant qu'`OSError`.

*Une correction à consigner :* le premier balayage annonçait **66** sites et était faux. Il n'inspectait que la clause `except` et ignorait le mot-clé `errors=`, si bien qu'il signalait `auth_log.py` et `ssh/_parsers.py`, qui passent déjà `errors="replace"` / `errors="ignore"` et ne peuvent pas lever. Pire, trois de ses « correctifs » passaient `errors=` à `file.read()`, qui n'accepte qu'une taille — ils auraient levé `TypeError` à l'exécution, et deux de ces sites décodaient déjà explicitement. Corrigé à 33 sites réels.

#### 3. `bob --history` mourait sur une seule ligne malformée

```python
try:
    entries.append(_clamp_entry(json.loads(line)))
except (json.JSONDecodeError, ValueError):
    continue
```

Une ligne contenant du JSON valide mais non-objet — `null`, `[1,2]`, `"str"` — se parse sans problème, puis atteint `_clamp_entry`, qui appelle `.get` dessus : `AttributeError`, que ce handler n'attrape pas, et le handler externe ne capture qu'`OSError`. La boucle a pour seule raison d'être d'ignorer les lignes malformées ; c'est désormais vrai pour toutes les formes de malformation, pas seulement pour celles qui ne se parsent pas.

#### 4. `--lang` acceptait un chemin absolu

La valeur allait directement à `i18n.init()`, qui construit `_LOCALES_DIR / f"{lang}.json"`. `pathlib` remplace toute la base quand la partie droite est absolue :

```python
>>> Path("bob/locales") / "/etc/hosts.json"
PosixPath('/etc/hosts.json')
```

Ainsi `--lang=/tmp/x` chargeait `/tmp/x.json` comme table de traduction — confirmé via le CLI — et sous `sudo` cette lecture s'effectue en root. Ce n'est pas un franchissement de frontière de privilège (l'opérateur possède déjà sa ligne de commande), mais c'est un argument non validé atteignant un chemin arbitraire du système de fichiers, dans un outil qui valide `SUDO_USER` par regex trois modules plus loin.

La validation porte sur la **forme** uniquement : `^[A-Za-z]{2,3}([_-][A-Za-z]{2,4})?$`. Un code bien formé mais non supporté (`--lang=de`) retombe toujours sur l'anglais avec un avertissement, exactement comme avant — seules les valeurs en forme de chemin sont rejetées.

#### 5. Les fichiers de rapport étaient ouverts sans `O_NOFOLLOW`

Le nom du rapport est entièrement prédictible à la seconde (`bob_%Y%m%d_%H%M%S.log`), l'ouverture s'exécute en root sous `sudo` avec `O_CREAT|O_TRUNC`, et le `chown_to_sudo_user(path)` qui suit re-résout le nom et suit les liens symboliques. Un attaquant capable d'écrire dans le répertoire cible pourrait pré-planter des liens sur une plage d'horodatages et faire tronquer par root — puis lui céder la propriété d' — un fichier arbitraire.

Le répertoire par défaut est le `~/.local/share/bob/logs` de l'utilisateur appelant : ce n'est donc **pas exploitable en sortie de boîte** ; il faut que l'opérateur ait pointé `--output-dir` vers un répertoire ouvert en écriture à d'autres. Le correctif est assez peu coûteux pour que la précondition ne justifie pas de le laisser : `O_NOFOLLOW` à l'ouverture, plus un nouveau `sysinfo.chown_fd_to_sudo_user()` opérant sur le descripteur déjà détenu, ce qui ferme la fenêtre TOCTOU entre l'ouverture et le chown.

#### 6. Injection de formules CSV

`csv.DictWriter` échappe correctement selon RFC 4180, mais Excel et LibreOffice évaluent quand même une cellule quotée commençant par `=`, `+`, `-` ou `@`. Du texte de rapport qui ne fait que *transiter* par BOB — une ligne de commande cron, un nom de conteneur, un chemin SUID — pouvait s'exécuter à l'ouverture de l'export :

```
x,2026-08-29T17:28:33+00:00,10,low,0,1,warn,action,"=cmd|""/C calc""!A1",@SUM(1+1)*cmd,+1234,
```

Les caractères de formule en tête de `message`, `detail`, `fix_cmd` et `note` sont désormais préfixés par une apostrophe — la mitigation standard. La cellule s'affiche comme du texte et la valeur d'origine est préservée verbatim après le préfixe. C'est un **changement mineur de format CSV** pour les consommateurs lisant ces quatre colonnes.

#### 7. Trois options n'avaient jamais reçu la garde tiret de v0.7.3 M-4

`--webhook`, `--ignore`, `--unignore`, `--output-dir`, `--explain` et `--diff` rejettent tous une valeur commençant par `-`. `-p/--profile`, `--check` et `--skip` n'ont jamais eu le même traitement, d'où :

```
bob -p --quiet          → profile="--quiet", et --quiet est avalé
bob --skip --quiet      → skip_checks={"--quiet"}, et --quiet est avalé
bob --check ""          → filtre vide (falsy) → lance l'audit COMPLET, en silence
bob --check ","         → idem
```

Les deux derniers sont les plus tranchants : `--check=` levait correctement une erreur, tandis que la forme séparée par une espace dégradait en « aucun filtre » sans un mot. Les quatre cas échouent désormais proprement.

#### Plus : un log de debug qui noyait son propre signal

`domain_scores.key_to_domain` journalise dès qu'un préfixe de clé de finding n'a pas d'entrée dans `_PREFIX_TO_DOMAIN`, pour qu'un développeur ajoutant un check remarque qu'il a oublié de le mapper. Mais `firewall` est le domaine catch-all documenté : le log se déclenchait donc ~40 fois par exécution pour des préfixes non mappés *à dessein* (`services`, `ports`, `docker`, `smtp`, `ipv6`…). Les préfixes délibérés sont maintenant listés dans `_INTENTIONAL_CATCHALL` et restent silencieux ; un garde échoue si l'un d'eux devient un jour mappé, pour que la liste ne puisse pas devenir silencieusement mensongère.

### Vérifié sain

La même campagne n'a trouvé aucun défaut dans les surfaces suivantes, qu'il n'est pas utile de ré-auditer : le parser d'argv (1 209 combinaisons hostiles, zéro exception hors `CLIError`), les 46 sections balayées individuellement sous user namespace restreint (zéro crash), 8 exécutions concurrentes (aucune corruption de fichier d'état, 0600 préservé, toutes les lignes d'historique intactes), tube rompu et stdout entièrement fermé, l'application du schéma webhook (`file://`, `gopher://`, `javascript:`, et `http://` en clair, tous rejetés), l'échappement HTML et Markdown, la gestion de `SUDO_USER`, la couverture `--explain` de tous les findings actionnables, et le parser `cap_last_cap` de v0.14.1 lui-même face à 13 entrées hostiles (zéro, négatif, 64, énorme, vide, non numérique, hexadécimal, flottant, NUL — tous retombent dans les bornes sans danger).

### Gardes

+64 tests dans `tests/test_v0141_robustness.py`, tous mutation-testés : neuf défauts ont été injectés un à un — restreindre la barrière à une sous-classe, réintroduire un site de snapshot impatient, retirer le champ `degraded_sections`, retirer `errors="replace"`, revenir sur la vérification de type de l'historique, retirer la validation de `--lang`, retirer `O_NOFOLLOW`, retirer le préfixe CSV, retirer la garde tiret — et chacun a produit un échec avant restauration du fichier.

Les gardes de la barrière sont structurels (assertions AST sur la vraie source de `runner.py`) plutôt que comportementaux, parce que `run_checks` n'est délibérément pas exercé dans la couche pytest — il relève de la matrice d'intégration, comme le documente `tests/test_runner.py`. La preuve comportementale est la reproduction live ci-dessus, avant et après.

### Deuxième manche — la campagne retournée contre ses propres correctifs

Le durcissement de la première manche a lui-même été attaqué, en même temps que la frontière système de fichiers qui le porte. Sept défauts de plus.

#### 1. La barrière pouvait être mise en échec depuis son propre handler

`_degrade_section` enregistrait la section, puis rendait l'échec — mais le rendu (`report.write_raw`, `t()`, `output.sanitize`, `add_finding`) se trouvait *hors* de son `try` interne. Une exception dans l'un d'eux s'échappait **depuis l'intérieur du gestionnaire d'exception**, remontait hors de `run_checks`, et reproduisait exit 3 avec zéro octet sur stdout : exactement la perte que la barrière existe pour empêcher, un niveau plus haut.

Quatre sondes ont été tirées ; deux sont passées par leurs propres mérites — un `t()` qui lève (clé de locale absente ou malformée), et une exception dont `__str__` lève. Les deux autres (un `sanitize` qui lève, un `write_raw` en échec) cassaient d'abord le noyau always-on, non protégé par conception.

Ce sont désormais deux étapes dans un ordre explicite : **enregistrer** — l'ajout à `_degraded` ne peut pas échouer, et c'est lui qui garde la section visible dans `degraded_sections` même quand plus rien d'autre ne peut s'exécuter — puis **rendre**, en best-effort, chaque étape faillible gardée individuellement, avec deux helpers totaux (`_safe_exc_text`, `_safe_section_message`) qui ne peuvent pas lever.

#### 2. Un disque plein coûtait l'audit entier

`AuditReport._writeln` était un `write()` + `flush()` nu, sans aucune gestion d'erreur, atteignable depuis environ 200 sites d'appel `report.write_*` répartis dans tout l'audit. `close()` était pire : il vidait le tampon sans garde à l'ultime étape, après que tout le travail était fait.

Reproduit sur un vrai tmpfs de 64 Ko :

```
$ sudo bob -d --output-dir=<système de fichiers plein>
EXIT=3 stdout=0B
Fatal error: [Errno 28] No space left on device
```

Un `/var` plein ou une partition de logs saturée est l'une des situations les plus ordinaires pour un administrateur — et précisément l'une de celles où il lancerait un audit de durcissement. Le rapport est un *artefact secondaire* ; le résultat de l'audit ne doit jamais en dépendre. Il se désactive maintenant à la première erreur d'E/S, le dit une fois sur stderr (stdout reste propre pour les formats machine), et l'audit se termine normalement.

#### 3. `--ignore` faisait taire le score, pas l'écran

`display_result()` parcourt le `CheckResult` brut, pas `engine.findings`. `engine.apply()` triait les findings ignorés dans `ignored_findings` sans les retirer du résultat : le terminal continuait donc de les afficher intégralement.

Mesuré, avant et après l'ajout d'une clé à `ignore.yml` :

```
AVANT   warning_count 14   ⚠ [WARNING] Fail2ban ... : 1 ligne
APRÈS   warning_count 13   ⚠ [WARNING] Fail2ban ... : 1 ligne
```

Le score et le JSON honoraient l'option. L'opérateur voyait toujours le finding — ce qui est toute la raison d'être de l'option. Avec `--show-ignored`, il était même affiché deux fois : une fois en avertissement, une fois dans le bloc gris des ignorés.

`engine.apply()` retire désormais les findings ignorés du `CheckResult` lui-même. `--show-ignored` n'est pas affecté : il rend depuis `engine.ignored_findings`. Ce défaut est aussi ancien que la fonctionnalité.

#### 4. Des séquences d'échappement terminal atteignaient le terminal

`output.sanitize()` existe, est documentée « à appliquer à toute donnée venant du système … avant affichage terminal », et elle est solide — elle retire ANSI, caractères de contrôle, forçages RTL et caractères de largeur nulle. Elle était appelée depuis **7 sites dans tout le code**.

Le texte des findings interpole partout ailleurs des valeurs venues du système : noms de fichiers, d'unités, d'utilisateurs, de paquets, sujets de certificats. Démontré avec un script world-writable dans `/etc/cron.daily` dont le *nom de fichier* portait une séquence OSC de changement de titre :

```
⚠ [WARNING] 1 script(s) ... world-writable: /etc/cron.daily/evil^[[31m^[]0;HIJACKED^Gjob
║       /etc/cron.daily/evil^[[31m^[]0;HIJACKED^Gjob                    ║
```

La séquence réécrivait le titre de la fenêtre et corrompait la boîte de résumé. Avec des séquences de déplacement du curseur, le même vecteur permet de réécrire des lignes d'audit déjà affichées — c'est-à-dire de faire mentir le rapport sur d'*autres* findings, ce qui pèse plus lourd dans un auditeur de sécurité que dans la plupart des outils.

L'assainissement se fait désormais dans `Finding.__post_init__` — par lequel passe toute construction par définition, y compris `bob/_sandbox.py` qui reconstruit un `Finding` depuis le JSON renvoyé par un plugin — de sorte que terminal, JSON, CSV, Markdown et HTML sont couverts par un seul changement. `cmd` conserve ses sauts de ligne via une nouvelle `sanitize_multiline()` (14 blocs de remédiation multi-lignes légitimes) et perd tout le reste. Sans effet mesuré sur du contenu normal : sur une exécution complète, 119 findings ne portaient aucun caractère de contrôle dans `message` / `detail` / `note`.

#### 5. Lectures non bornées sur des chemins non réguliers

Le chargeur de plugins avait un plafond de 64 Ko — appliqué via `stat().st_size`, qui n'est une longueur que pour un fichier régulier. Un périphérique caractère déclare `0` :

```
$ ln -s /dev/zero ~/.config/bob/checks.d/p.py
$ sudo bob            # → tué par l'OOM killer (exit 137)
```

La même classe de défaut traversait tous les lecteurs d'état, qui utilisaient tous un `read_text()` nu :

| chemin | avant |
|---|---|
| `--diff=/dev/zero` | mémoire épuisée, exit 3 |
| `--diff=<fifo>` | **blocage indéfini** |
| `ignore.yml` → `/dev/zero` | toutes les exécutions fatales |
| `last_baseline.json` → `/dev/zero` | toutes les exécutions fatales |
| `history.jsonl` → `/dev/zero` | `bob --history` fatal |

Le FIFO est le pire du lot : un cron reste suspendu au lieu d'échouer, et recommence à chaque exécution suivante. Et `--diff=PATH` accepte un chemin arbitraire fourni par l'opérateur : une simple faute de frappe y mène, pas seulement une auto-sabotage.

Un nouveau `bob._atomic.read_text_capped()` partagé refuse tout ce qui n'est pas un fichier régulier (ce qui couvre périphériques, FIFO, répertoires et sockets) et borne la lecture elle-même, reprenant le motif de lecture bornée que `i18n._load_locale` utilise depuis toujours. L'ordre y compte : un fichier *absent* doit toujours lever `FileNotFoundError`, car `compare.load_baseline` s'en sert pour produire le message « baseline introuvable » distinct de v0.9.2 — s'être trompé sur ce point a été rattrapé par les gardes de cette release-là.

#### 6. Ctrl-C affichait un traceback

Interrompre un audit long déversait une pile Python brute se terminant par `KeyboardInterrupt`. Le code de sortie était déjà le 130 conventionnel ; seul le bruit était fautif. `main()` l'attrape désormais et affiche une ligne localisée (EN + FR).

### Vérifié sain

Aucun défaut trouvé, et à ne pas ré-auditer : **12 000 combinaisons d'argv** de 2 à 4 options (zéro exception hors `CLIError`, zéro état contradictoire — les drapeaux de format de sortie conflictuels sont correctement rejetés, contrairement à une hypothèse de la première manche) ; le dry-run `--fix`, instrumenté au niveau de `subprocess.run` — **zéro** appel provenant de `bob/fixes.py` ; le déterminisme de l'audit (trois exécutions structurellement identiques) ; SIGINT / SIGTERM / SIGHUP / SIGPIPE (130/143/129/141) ; `HOME` non défini, inexistant, ou pointant vers un système de fichiers en lecture seule ; `--watch` y compris son chemin d'interruption ; un log UFW de 34 Mo et 300 000 lignes parsé en 3,5 s sous espace d'adressage borné ; `sanitize()` face à 16 charges d'échappement dont OSC, CSI, forçage RTL et largeur nulle ; 6 des 7 plugins adversariaux déjà gérés par le bac à sable existant ; et les données de paquet corrompues, qui échouent vite avec des erreurs descriptives.

### Gardes

+32 tests dans `tests/test_v0141_hostile_io.py`, tous mutation-testés. Six défauts ont été réinjectés un à un et chacun a produit un échec avant restauration du fichier. L'un d'eux mérite d'être signalé : retirer la vérification « fichier régulier » ne fait pas *échouer* le test FIFO — il le fait **bloquer**, ce qui est précisément le symptôme de production que la garde existe pour empêcher.

### Troisième manche — ce que l'outil dit, plutôt que ce qu'il fait

#### 1. Le profil actif n'apparaissait que dans le terminal

Depuis v0.14.0, le profil d'audit change réellement les sévérités des findings, `warning_count` et donc le code de sortie. Il n'était rapporté que sous forme d'une ligne INFO dans la sortie texte du terminal — JSON, Markdown, HTML et CSV n'en portaient aucune trace.

Les conséquences sont concrètes : deux charges JSON du même hôte peuvent différer par leurs compteurs sans que rien ne l'explique ; un pipeline agrégeant des hôtes ne peut pas les regrouper par profil ; et un rapport Markdown ou HTML archivé n'indique jamais contre quoi il a été audité.

Un champ `profile` est désormais émis en JSON — additif dans le schéma v3, le même traitement que `degraded_sections` — et rendu dans les blocs d'en-tête Markdown et HTML (libellés EN + FR). **Le CSV est délibérément laissé de côté** : ajouter une colonne décalerait une seconde fois les lecteurs par index dans une même release, et le préfixage anti-injection de formules modifie déjà ce format. Consigné ici plutôt que fait en silence, pour que l'omission soit une décision et non un oubli.

#### 2. `-p NOM` devient silencieusement votre défaut permanent

`bob/__main__.py` persiste un profil valide via `user_config.set_profile()`. C'est délibéré — v0.12.1 avait corrigé un défaut voisin où un nom *invalide* était persisté — mais ce n'est documenté ni dans `--help` ni dans les READMEs.

Ainsi `sudo bob -p container`, tapé une fois pour voir ce que dit le profil conteneur, réécrit le profil enregistré de l'opérateur pour toutes les exécutions suivantes. Cette campagne s'y est fait prendre : dix minutes passées à s'étonner d'un audit annonçant `container` sur un poste de bureau avant que la cause ne devienne évidente, et il a fallu restaurer le `config.conf` réel de la machine.

Le comportement reste ; `--help` et les deux blocs d'usage des READMEs le disent désormais.

#### 3. Les deux READMEs documentaient `-d` comme « sortie en français »

```
sudo bob -d                       # sortie en français        ← faux
```

`-d` est `--detailed` — enregistrer le rapport complet dans un fichier. `--french` est l'option de langue. La ligne était livrée dans les deux READMEs et avait survécu à la passe d'exactitude documentaire de v0.13.4.

Corrigée en EN et FR, avec deux gardes : l'un fait passer chaque exemple d'usage des READMEs par le vrai `parse_args` (ce qui attrape une option inventée ou renommée), l'autre rejette tout exemple dont le commentaire annonce du français alors que la commande ne porte aucune option de langue.

#### 4. La date de release avait de nouveau dérivé

Les surfaces v0.14.1 étaient encore datées du 2026-08-29, désormais inatteignable. Passées au **2026-08-30** (un dimanche) sur les lignes de tableau et les titres de section des changelogs, les entrées debian et rpm, les trois lignes `.TH` des pages de man, ainsi que l'en-tête et la ligne « release surface dated » du SNAPSHOT. C'est la dérive même pour laquelle v0.14.0 avait été corrigée — rattrapée cette fois avant publication et non après. Si la publication glisse au-delà du 30, il faudra recommencer.

### Vérifié sain

- **Tout l'espace de clés i18n.** 966 clés littérales extraites de la source, plus **637 expansions construites à l'exécution** — `sections.*` pour les 46 sections du runner, `groups.*`, `domain_scores.*`, `scoring.level.*`, `explain.*.{title,why,how}` pour les 169 clés, `service_risk.*` pour les 38 services enregistrés — toutes résolvent dans les **deux** locales. Rien ne peut atteindre un opérateur sous forme de `[clé]` entre crochets. `bob/cli.py` n'appelle `t()` nulle part : la classe du hotfix v0.9.1 (traduire avant `i18n.init`) reste fermée. Ce point pèse davantage depuis v0.14.1 : `_degrade_section` résout `sections.<nom>` pour la section qui a échoué.
- **Les invariants de score sur 6 000 états de moteur aléatoires** : score et scores de domaine entre 0 et 10 ; `alert_count` / `warning_count` / `info_count` conformes aux findings réellement conservés ; aucune déduction négative ; la règle F1 (« le 10/10 est réservé à un audit sans rien à corriger ») jamais violée ; plafonds de domaine respectés. Cela revalide au passage la modification de la deuxième manche qui retire les findings ignorés du `CheckResult`.
- **Le chargeur de profils** face à des profils circulaires (`a → b → a`), auto-référentiels, profonds de 15 niveaux, binaires malformés, en traversée de chemin, en chemin absolu et liés à `/dev/zero` : chacun dégrade vers le défaut avec un avertissement visible, aucun ne bloque ni ne plante.
- **La conformité du schéma JSON sur 16 charges utiles** — 4 profils × 2 formats × 2 langues — sans clé requise manquante, sans clé non déclarée, sans clé réservée au mode complet fuitant dans le mode normal, et avec les types corrects pour les nouveaux champs `degraded_sections` et `profile`.
- **`--watch` sur des itérations répétées** : descripteurs de fichiers stables, aucune tendance de croissance établie sur les itérations observées.

### Gardes

+16 tests dans `tests/test_v0141_contract_surfaces.py`, tous mutation-testés : retrait de la clé de schéma `profile`, retour en arrière sur la ligne de persistance de `--help`, restauration de l'exemple erroné du README, suppression d'une entrée de locale `sections.*`, et désactivation du plafond F1 — cinq injections, cinq échecs confirmés.

### Documentation

Une passe complète sur le corpus documentaire — les READMEs, `SECURITY`, `AUTOMATION`, `TESTING`, `TUTORIAL`, les références technique et développeur et le `SNAPSHOT` — pour les aligner sur cette release et réconcilier la parité EN/FR. Le `SNAPSHOT` a de plus été vérifié affirmation par affirmation contre le code qu'il décrit.

### Tests

6590 → **6719** (+129 sur v0.14.0 : 17 pour la sémantique privileged, 64 + 32 pour les deux lots robustesse, 16 pour les surfaces de contrat). 0 régression.

Mise à jour : `pipx upgrade bodyguard-of-bits` — aucune action de migration. Les audits conteneur rapportent désormais le finding exact ; tout le reste est inchangé.

---

## [v0.14.0] — 29-08-2026

**Bundle BREAKING de corrections de contrat. Les « dents » auxquelles cette version était réservée restent reportées.**

La v0.14.0 était prévue comme la release transformant les signaux runtime de v0.13.x en déductions de score — conteneurs privilégiés, parité de scoring nftables. Les calibrer exige un vrai conteneur et une vraie instance cloud pour le field test, et aucun des deux n'est disponible. La règle inscrite au backlog est *ne pas deviner* : elles attendent.

À la place, trois défauts de contrat trouvés en auditant l'outil contre lui-même, plus les items de lint et de packaging différés tout au long de v0.13.x.

### 🔴 Le profil d'audit n'atteignait jamais 12 des 14 chemins de résultat

Jusqu'ici, il incombait à l'appelant d'invoquer `apply_profile()` avant `engine.apply()`. Dans `bob/runner.py`, sur les 14 sites `engine.apply()`, exactement deux le faisaient : le helper générique `_sec` et le chemin plugin. Les douze autres — toutes les sections always-on écrites à la main — non :

```
firewall · firewall_rules · ufw_logging · firewall_iptables · firewall_drivers
network_context · services · ports · logs · ddns · docker · virtualization
```

Tout override de profil visant l'une d'elles était donc inerte. Huit sont livrés d'origine :

| Override (desktop.conf et workstation.conf) | Effet jusqu'à v0.14.0 |
|---|---|
| `ddns.warn = info` | mort |
| `services.exposed.avahi = info` | mort |
| `services.exposure.open_local = info` | mort |
| `firewall_drivers.ip_forward_enabled = info` | mort |

Mesuré en live avant le fix, `services.exposure.open_local` remontait WARN sur les **trois** profils, y compris les deux dont le `.conf` le déclare INFO.

La conséquence dépasse le cosmétique. `warning_count` compte par *niveau*, pas par nature, et `bob/__main__.py` mappe `warning_count > 0` sur `EXIT_WARNINGS`. Un hôte avec Samba restreint au LAN par une règle UFW — la configuration que BOB recommande lui-même — retournait donc exit 1 en permanence, et l'`exit 0` (« No issues detected », partie de l'API stable des codes de sortie) était inatteignable quelle que soit la configuration.

`ScoreEngine` reçoit désormais `profile=` et applique les overrides dans `apply()` — le point de passage unique par lequel chaque résultat doit transiter. L'alternative, répéter l'appel devant chaque `engine.apply()`, a été écartée : c'est précisément le design qui a dérivé, et la prochaine section écrite à la main l'oublierait à son tour.

L'application du profil intervient **en premier** dans `apply()`, avant l'accumulation des déductions et des findings, parce qu'un profil peut retirer une déduction ou supprimer entièrement un finding (`skip`). L'import est paresseux — `bob.profiles` importe `CheckResult` et `FindingLevel` depuis `bob.scoring`, un import au niveau module serait circulaire.

`bob/watch.py` construit son propre engine et se laisse facilement oublier ; il aurait silencieusement perdu les overrides en mode watch. Il transmet `profile=` lui aussi, et un garde vérifie que tous les sites de construction le font.

**Vérifié en live, 4 profils × 2 locales :**

```
server       warn 13 -> 13    (baseline stricte préservée — aucun override livré)
desktop      warn  4 ->  2    (deux findings open_local passent INFO)
workstation  warn  4 ->  2
container    warn       ->  2
```

Le score est inchangé partout : `open_local` ne portait aucune déduction. EN et FR identiques sur chaque profil.

**Pourquoi cela a survécu si longtemps :** la suite complète passait *aussi* avant le fix. `tests/test_profiles.py` exerce `apply_profile` en isolation ; rien ne testait que le runner l'appelait réellement. Les nouveaux gardes sont donc comportementaux plutôt que structurels — l'ancien design était « correct » à chaque site qui y pensait.

### La couleur est auto-détectée (BREAKING)

`bob > rapport.txt` écrivait des séquences ANSI dans le fichier. `bob | less` les affichait brutes. `output.supports_color()` existait depuis longtemps : correcte, et appelée nulle part.

Ordre de résolution dans `output.init()`, première correspondance gagnante :

1. `--no-color` / `--no-colour` — demande explicite, gagne toujours
2. `NO_COLOR` non vide (v0.13.3 ; une valeur vide est ignorée, selon [no-color.org](https://no-color.org))
3. `FORCE_COLOR` non vide — **nouveau**, l'échappatoire pour `bob | less -R` ou pour capturer volontairement un log couleur
4. `stdout.isatty()` — le changement proprement dit

`supports_color()` ne lève plus non plus sur un stdout détaché ou fermé : certains harnais de capture remplacent `sys.stdout` par un objet dont `isatty()` échoue.

`print_help` codait `\033[1m` en dur pour ses en-têtes de section, donc `bob --no-color --help` affichait du gras malgré tout et `bob --help > fichier` y écrivait des séquences. Cela précède cette release — le texte d'aide ne passait simplement jamais par la machinerie couleur. C'est désormais le cas, et un garde interdit les séquences littérales dans `bob/cli.py` pour que le contournement ne revienne pas.

Mesuré : chemin d'audit 0 séquence en pipe / 50 avec `FORCE_COLOR` ; `--help` 0 en pipe, 10 forcé, 0 avec `--no-color` même forcé.

Quatre tests existants affirmaient l'ancien contrat (« par défaut = couleur »). Ils affirment maintenant les deux moitiés du vrai. La sonde `NO_COLOR` de `tests/test_v0133_release.py` pose `FORCE_COLOR` en permanence pour que la nouvelle dimension TTY ne puisse pas décider du résultat — sans cela elle passerait pour la mauvaise raison, stdout n'étant pas un terminal sous pytest.

### Formulation de `--help`

Reportée ici depuis la v0.13.4 à dessein, pour que le texte décrive le comportement final au lieu d'être corrigé deux fois. La ligne disait :

```
-n, --no-color   Disable colour output (--no-colour and NO_COLOR= also work)
```

`NO_COLOR=` se lit soit comme l'affectation `NO_COLOR=1`, soit comme la valeur vide — or la valeur vide est exactement le cas qui ne désactive *pas* la couleur. C'est désormais une entrée explicite nommant les deux variables d'environnement et indiquant que la couleur est auto-détectée.

### B904 / B905 — les derniers ignores ruff disparaissent

Différés tout au long de v0.13.x parce que leurs corrections changent le comportement à l'exécution, ce qui n'avait pas sa place dans un patch. Quatre sites `B904`, deux réponses différentes, car la bonne dépend de la valeur diagnostique de l'exception d'origine :

- **`bob/cli.py` (2 sites) — `from None`.** La `ValueError` d'`int()` est un détail d'implémentation du parsing d'arguments. Sous `BOB_DEBUG=1`, qui affiche la traceback complète, l'utilisateur verrait sinon *« during handling of the above exception »* devant une simple faute de frappe. Vérifié : `__suppress_context__` vaut désormais `True`.
- **`bob/_sandbox.py` (2 sites) — `from exc`.** L'inverse s'applique : quelle `OSError` (EACCES ? ENOENT ?) et où la `SyntaxError` est tombée, c'est exactement ce dont un auteur de plugin a besoin. Vérifié : `__cause__` est préservé.

`B905` — un `zip()` dans `bob/cron/_parse.py` appariant les 5 champs cron à `_CRON_FIELD_BOUNDS`. La regex juste au-dessus garantit déjà exactement 5 champs et la table en contient 5, donc `strict=True` ne peut pas se déclencher aujourd'hui ; il documente l'invariant, et si une 6ᵉ borne est un jour ajoutée sans toucher la regex, le validateur échoue bruyamment au lieu de ne vérifier silencieusement que les cinq premiers.

Aucun test nouveau pour ces points : la barrière elle-même est le garde, maintenant que `.ruff.toml` n'ignore plus rien.

### Jours de semaine des changelogs de packaging

Cinq entrées de `debian/changelog` et trois de `bob.spec` nommaient le mauvais jour pour leur date — `lintian debian-changelog-has-wrong-day-of-week`, qui remonterait à la première vraie revue de packaging Debian. Deux des entrées debian viennent de v0.13.3 et v0.13.4 ; les autres leur sont antérieures. Les 46 entrées de chaque fichier sont désormais correctes, avec un garde qui recalcule le jour depuis la date.

### Gardes

+43 sur quatre fichiers, tous mutation-testés : un vrai défaut est injecté, l'échec confirmé, le fichier restauré.

- `tests/test_v0140_profile_wiring.py` — un override doit atteindre l'engine ; un downgrade doit retirer la déduction, pas seulement l'étiquette ; `apply` doit rester idempotent pour qu'un `apply_profile` manuel ne double-pénalise pas ; `runner.py` ne doit plus appeler `apply_profile` ; toute construction de `ScoreEngine` doit passer `profile=`.
- `tests/test_v0140_colour_resolution.py` — la matrice de précédence complète à 8 cas, un contrôle AST que `init()` appelle bien `supports_color()`, le chemin stdout détaché, quatre cas `--help` de bout en bout, et aucune séquence littérale dans `bob/cli.py`.
- `tests/test_v0134_docs_accuracy.py` — les deux gardes de jours de semaine.

### README — la table des codes de sortie était fausse, et non gardée

Vérifier les README contre cette release a fait remonter un défaut plus ancien qu'elle : `README.md` et `README_FR.md` mappaient chaque code de sortie sur une **plage de score** —

```
| 0 | Score >= 7 — aucun problème significatif |
| 3 | Score 0 — problèmes critiques            |
```

— alors que les codes sont pilotés par le *nombre* de findings, et que `3` est `EXIT_ERROR`, une **erreur technique**. Un audit qui échoue ne sort jamais en 3. `--help`, `DOCUMENTS/README_TECH.md` et `bob/__main__.py` étaient tous d'accord entre eux ; seuls les deux documents les plus lus ne l'étaient pas. Les deux portent désormais le vrai contrat avec le nom des constantes, plus une note explicite indiquant que `3` n'est pas un mauvais score et que `--target N` est le moyen de poser un seuil en CI.

Un garde (`TestExitCodesAreDocumentedCorrectly`) épingle chaque ligne `` `N` | `EXIT_*` `` des quatre documents contre les vraies constantes de `bob.__main__`, exige que chaque constante soit documentée, et rejette catégoriquement toute formulation en plage de score dans cette table. Mutation-testé en restaurant la ligne d'origine.

Corrigé au passage :

- **Le cadrage de la couleur** — `README_TECH{,_FR}.md` annonçait *« `--no-color` pour une sortie propre dans les pipes et fichiers log »*. Vrai, mais obsolète : depuis cette release c'est automatique. Réécrit pour décrire l'auto-détection, avec `--no-color` / `NO_COLOR` / `FORCE_COLOR` comme forçages.
- **Une nouvelle table de variables d'environnement** dans `README_TECH{,_FR}.md`. `NO_COLOR`, `FORCE_COLOR`, `BOB_DEBUG` et `BOB_SHARE` étaient documentées dans `SECURITY.md` mais absentes du README technique — `FORCE_COLOR`, nouvelle échappatoire visible par l'utilisateur, n'y figurait nulle part. La table énonce la chaîne de précédence de la couleur.
- **Les exemples `ScoreEngine()`** — `README_DEV{,_FR}.md` (diagramme de flux et extrait de calcul du score) ainsi que le contrat d'usage de `SNAPSHOT.md` montraient tous un `ScoreEngine()` nu. Après cette release, c'est précisément la construction qui n'applique **aucun** override de profil — le défaut que la release corrige. Tous montrent maintenant `ScoreEngine(profile=active_profile)` avec la raison.
- **La liste des profils** dans la prose de `README{,_FR}.md` nommait `server` / `workstation` / `container` en omettant `desktop`, alors que la table juste en dessous listait les quatre.

### Validation — ce qui est couvert, et ce qui ne l'est pas

Une seconde passe de validation a été menée une fois la release assemblée, ciblant les chemins d'interaction que la première n'avait pas exercés. Elle n'a trouvé **aucun défaut** ; rien n'a été modifié dans cette release en conséquence. Ce qu'elle a couvert :

| Chemin | Résultat |
|---|---|
| Action `skip` d'un profil (retire entièrement un finding) | correct via `engine.apply()` |
| Downgrade retirant la déduction attachée | correct — le score remonte à 10 |
| Ordre profil × `ignore.yml`, 4 combinaisons | correct, et le cas sans profil se comporte toujours comme en v0.13.4 |
| Mode `--watch`, itérations réelles | profile-aware — server 8/10, desktop 9/10, cohérent avec l'audit normal |
| Findings de plugin | reçoivent le profil : server WARN, desktop INFO |
| Sorties machine (json, json-full, csv, markdown, html) | zéro ANSI, en pipe **et** sur TTY |
| Couleur de `--breakdown` sur un vrai terminal | 16 séquences, identique à v0.13.4 — pas de régression |

Régression complète contre v0.13.4, sur les quatre profils :

```
server       score 8 warn 13  128 findings   IDENTIQUE
desktop      score 9 warn  4 → 2             seul services.exposure.open_local change
workstation  score 9 warn  4 → 2             idem
container    score 9 warn  4 → 2             idem (extends = desktop, hérite l'override)
```

Exactement une clé de finding change de niveau, sur exactement les profils qui déclarent l'override. Aucun dommage collatéral.

**Ce qui n'est _pas_ validé, et ne doit pas être lu comme tel :**

- **Le comportement cloud à l'exécution.** Seul le chemin de détection du provider par DMI a été exercé, en bind-montant des fixtures sur `/sys/class/dmi/id` dans un conteneur : 11 providers détectés, 2 négatifs rejetés. Ces fixtures ont été *écrites pour le test* — cela vérifie que le matcher fonctionne **étant données** ces valeurs DMI, pas que Hetzner, Linode ou Alibaba les publient réellement. Les findings que le check émet à l'exécution — `cloud_context.imds_reachable` et le cas user-data lisible par tous — **ne se sont jamais déclenchés**. Ils exigent une vraie instance cloud.
- **Trois des quatre overrides de profil ressuscités.** `ddns.warn`, `services.exposed.avahi` et `firewall_drivers.ip_forward_enabled` sont vérifiés par test ciblé contre les vrais fichiers `.conf` livrés et le vrai engine (8 cas sur 8, aucun skippé), mais cet hôte n'émet pas ces findings : aucun n'a donc été observé sur un audit live. Seul `services.exposure.open_local` l'a été.
- **Les checks `docker` et `docker_hardening`.** Ils gatent sur `_command_exists("docker")`, et le runtime retenu pour le field test est podman — délibérément, parce qu'installer Docker ajouterait un daemon, des règles iptables et un bridge, modifiant la posture de l'hôte qui sert justement de référence de comparaison. Ces deux checks restent non exercés contre un vrai hôte Docker.

### Deux constats issus du field test, non corrigés ici

Tous deux relèvent des « dents » différées ; ils sont consignés plutôt que corrigés, pour que la prochaine release parte de preuves et non d'hypothèses.

**Le titre de `container_security.privileged` sur-affirme.** Avec un vrai conteneur disponible pour la première fois, la matrice à quatre cas donne :

```
défaut rootless       cap_bnd 2147747323     seccomp 2   privileged False
--privileged          cap_bnd 2199023255551  seccomp 0   privileged True
--cap-add SYS_ADMIN   cap_bnd 2149844475     seccomp 2   privileged True   <--
seccomp=unconfined    cap_bnd 2147747323     seccomp 0   privileged False
```

`privileged` est *défini* comme « CAP_SYS_ADMIN est présent » (`container_security.py:75`), et le détail du finding est prudent — *« Un conteneur privilégié (ou doté de CAP_SYS_ADMIN) »*. Le titre ne l'est pas : *« Le conteneur semble PRIVILÉGIÉ — jeu complet de capabilities Linux disponible »*. Pour un conteneur doté d'une seule capability ciblée, le jeu complet n'est démonstrativement **pas** disponible, et seccomp filtre toujours. Cela compte pour la déduction prévue : le backlog liste `privileged` et `CAP_SYS_ADMIN` comme deux conditions distinctes alors que le code les confond — keyer une déduction sur `privileged` tel que calculé aujourd'hui pénaliserait un conteneur à portée étroite (un montage FUSE, par exemple) exactement autant qu'un conteneur pleinement privilégié.

**La parité de scoring nftables n'a en réalité jamais été bloquée.** Le backlog la classait parmi les dents en attente de matériel de field test, mais ce blocage portait sur les conteneurs et les instances cloud. `nft` et `iptables-nft` sont présents sur une station de travail ordinaire : le travail de parité peut être calibré dès qu'il sera planifié — aucun matériel ne manque pour lui.

### Tests

6547 → **6590**. 0 régression. ruff : 0 finding, plus rien d'ignoré.

Mise à jour : `pipx upgrade bodyguard-of-bits`. **BREAKING** — les audits desktop/workstation rapportent moins d'avertissements et peuvent désormais sortir en 0 là où ils sortaient toujours en 1 ; la sortie redirigée perd ses couleurs sauf si `FORCE_COLOR=1` est posé.

---

## [v0.13.4] — 28-08-2026

**Passe d'exactitude documentaire. Corrections factuelles uniquement — aucune réécriture d'un texte déjà correct, aucun changement de comportement d'audit.**

Un audit machine du corpus documentaire complet (21 fichiers markdown, 3 pages de man, ~26 kLignes) confronté au code. Sept défauts réels ; **deux ont été introduits par la v0.13.3 elle-même**, et c'est précisément l'enseignement : une release qui change un comportement doit balayer la doc à la recherche des affirmations qu'elle vient de rendre fausses — or la v0.13.3 n'avait mis à jour que l'en-tête du SNAPSHOT et le changelog.

### 🔴 La section « Plugin checks » de `SECURITY_FR.md` était factuellement inversée, pas seulement amputée

La section mesurait 83 mots contre 562 en anglais (**15 %**), alors que les 15 autres sections du même fichier étaient à 107–132 %. Mais le volume était le moindre problème. Le texte français disait :

> les plugins […] **NE SONT PAS sandboxés** […] Une future version majeure pourra introduire un runner de plugins en mode restreint […] mais c'est hors périmètre pour la ligne **0.6.x**.

Le sandbox est livré depuis la **v0.7.0**. Pendant **sept versions mineures**, la politique de sécurité française a dit à ses lecteurs l'inverse de la vérité, et a figé la feuille de route sur une ligne en fin de vie depuis la v0.7.2.

Tout ce que la version anglaise dit du modèle de menace était absent en français : qu'un sandbox Python in-process **n'est pas une frontière de sécurité** (PEP 416, retirée) ; que `json.dumps.__globals__["__builtins__"]["__import__"]` est atteignable par n'importe quel plugin et que c'est *attendu* et épinglé par `TestKnownInProcessLimitation` ; que le contournement non lié `dict.__setitem__` est une limitation connue ; que **AppArmor est la véritable frontière** ; et la conclusion opérationnelle — **si vous exécutez BOB non confiné sous `sudo`, relisez le code de vos plugins avant de les installer**.

La section est désormais intégralement traduite, y compris l'isolation par spawn, les rlimits, la liste blanche d'imports, la justification d'`_ImmutableBuiltins`, le wrapper `open()`, l'aller-retour JSON-safe qui défait un `__reduce__` malveillant, et la note sur `BOB_SANDBOX_LEGACY` retirée. **15 % → 121 %**.

### Cinq options CLI fonctionnelles n'apparaissaient nulle part dans `--help`

Les cinq sont correctement parsées et utilisées ; aucune n'était découvrable :

| Option | Vérifié | Présente dans `--help` |
|---|---|---|
| `--json` | `json_mode=True` | non |
| `--json-full` | `json_full=True` | non |
| `--html` | `html_mode=True` | non |
| `--output=FORMAT` | `csv_mode=True` | non — le grep matchait `--output-dir` |
| `--no-colour` | `no_color=True` | non |

C'est la classe « silent feature gap » que le projet avait chassée sur huit tiers en v0.8.0. `--output=FORMAT` est désormais documentée avec un avertissement explicite pour ne pas la confondre avec `--output-dir`, et `--no-colour` / `NO_COLOR` sont mentionnées sur la ligne `--no-color`.

### 29 liens markdown cassés ou fuités

- **17** dans `DOCUMENTS/CHANGELOG_FULL.md` écrits `](bob/…)` au lieu de `](../bob/…)`. Ils résolvent vers `DOCUMENTS/bob/…` et renvoient 404 sur GitHub. Le jumeau français en avait **zéro** — ce qui explique exactement pourquoi la symétrie entre locales ne les a jamais fait remonter.
- **8** pointant vers `](memory)` — des références au magasin de mémoire interne de Claude qui avaient fuité dans les changelogs publics, répartis sur quatre fichiers. Ils ne signifient rien pour un lecteur et ne résolvent vers rien dans le dépôt ; remplacés par la règle en langage clair qu'ils citaient.
- **4** cibles obsolètes : `bob/checks/ssh.py` (splitté en paquet en v0.6.0) et une URL `bob/_v090_renames.py::remap_finding_key` où le suffixe `::méthode` rendait le chemin invalide.

### `SNAPSHOT.md` se contredisait après la v0.13.3

La ligne 15 (ajoutée par la v0.13.3) disait `NO_COLOR` honorée. La ligne 633 disait encore :

> **NOT honored** : `NO_COLOR` env var. BOB currently respects only the `--no-color`/`-n` CLI flag.

Résolu. Le remplacement énonce aussi la partie qui reste vraie et facile à confondre : l'auto-détection TTY n'est toujours pas câblée — `output.supports_color()` existe, est correcte, et n'est appelée nulle part, donc BOB émet de l'ANSI même dans un pipe. L'activer est BREAKING et reste réservé à la v0.14.0 avec une échappatoire `FORCE_COLOR`.

### `BOB_DEBUG` était documentée comme traceback seulement

`SECURITY.md` et `SECURITY_FR.md` la décrivaient comme « affiche la trace Python complète sur sortie `EXIT_ERROR=3` » — vrai depuis la v0.6.1, et incomplet depuis hier : la v0.13.3 lui a en plus fait installer un vrai handler de logging sur le logger `bob`. Les deux tables décrivent maintenant les deux effets. `NO_COLOR`, entièrement absente des tables d'environnement, y a été ajoutée dans les deux locales.

### `README_DEV` omettait les quatre modules de check v0.13.x

`systemd_hardening`, `container_security`, `socket_units` et `cloud_context` avaient **0 occurrence** dans `README_DEV{,_FR}.md` contre 3–4 chacun dans `SNAPSHOT.md`. Ajoutés au tableau des modules et à l'arborescence, dans les deux locales. `--english` (v0.12.1) était de même absente de `README_TECH{,_FR}.md` et de `man/bob.1`.

### Trois gardes anti-drift

Chacun ferme une classe plutôt que les instances trouvées :

1. **Résolution des liens** — tout lien markdown relatif doit résoudre ; aucun `](bob/` depuis `DOCUMENTS/` ; aucun lien vers le magasin de mémoire. Deux exemptions de faux positifs documentées (un exemple littéral de syntaxe `[label](url)` et une regex dans un bloc de code).
2. **Ratio de mots EN/FR par section ≥ 55 %.** La granularité *par section* est l'essentiel : `SECURITY_FR.md` était à **92 % globalement**, donc un ratio par fichier aurait entièrement raté la section inversée.
3. **Couverture de la surface CLI** — toute option acceptée par `parse_args()` doit figurer dans `--help`, plus la vérification inverse que `--help` ne promet rien que le parseur refuse. Écrire ce garde a immédiatement exposé un bug dans sa propre extraction : les options à valeur sont matchées via `arg.startswith("--webhook-format=")`, donc le littéral porte un `=` final à l'intérieur des guillemets et une regex naïve signale une option fonctionnelle comme fantôme. Corrigé avant que le garde ne soit considéré comme fiable.

### Vérifié sain — délibérément non touché

Les résultats négatifs de l'audit comptent autant que ses trouvailles, et ils bornent toute passe future :

- **5 paires de docs sur 6 à 106–113 %** de ratio de mots EN/FR (README, README_TECH, README_DEV, AUTOMATION, TUTORIAL) — les traductions sont complètes ; le français est simplement plus long.
- **`CHANGELOG_FULL` porte les 65 releases dans les deux locales**, aucune manquante. L'écart de 1755 lignes est de la mise en forme, pas du contenu.
- **L'inventaire des modules de `README_DEV` est par ailleurs complet** — aucun module fantôme, aucun module racine manquant. Il est organisé par *nom de fichier* (`docker_audit.py`, `services_state.py`), qui sont les vrais noms ; les renommages de *sections* de la v0.9.0 D-1 sont une surface distincte et purement interne.

### Tests

6533 → **6545** (+12, tous dans `tests/test_v0134_docs_accuracy.py`). 0 régression.

**v0.12.x reste EOL** ; v0.13.x est la seule ligne supportée. Mise à jour : `pipx upgrade bodyguard-of-bits` — documentation et texte de `--help` uniquement.

---

## [v0.13.3] — 28-08-2026

**Patch de durcissement. Additif, non-BREAKING, sans changement de score, sans modification d'un champ de sortie ou d'un code de retour.**

Cinq items, tous trouvés en auditant l'outil contre lui-même plutôt que par remontée utilisateur. Chacun a été vérifié en reproduisant le défaut avant de le corriger.

### 🔴 Les `logger.warning` fuyaient bruts sur stderr — `--quiet` et i18n contournés

BOB n'a jamais appelé `logging.basicConfig` ni installé de handler nulle part. Le handler *lastResort* de Python attrapait donc les ~45 sites `logger.warning` / `logger.error` du paquet et les affichait sur stderr — sans préfixe de niveau, sans i18n, et sans égard pour `--quiet` (documenté « supprime toute sortie »).

Le symptôme le plus visible était un message doublé :

```
$ sudo bob --profile=bogus --quiet
Warning: Profile 'bogus' not found — using default (server)     <- output.print_warn (i18n, préfixé)
Profile 'bogus' not found — using default (server)              <- profiles.py:134 logger.warning
```

Le garde `_profile_prewarned` de `bob/__main__.py` supprimait correctement le *second avertissement formaté par BOB* ; il ne pouvait rien contre l'enregistrement du logger derrière.

Le correctif tient en deux lignes dans [bob/__init__.py](../bob/__init__.py) :

```python
logging.getLogger(__name__).addHandler(logging.NullHandler())
```

Le mécanisme est important et a été vérifié empiriquement : `logging.lastResort` ne se déclenche **que** si zéro handler est trouvé en remontant la hiérarchie. Un `NullHandler` sur `bob` compte comme handler trouvé, donc lastResort est désactivé — mais `propagate` reste `True`, donc les enregistrements atteignent toujours le logger root. Confirmé par une sonde à trois cas (aucun handler → fuite ; NullHandler → silence ; NullHandler + handler root → propage toujours) et en exécutant la suite complète, y compris les trois tests qui utilisent `caplog`.

Museler les diagnostics sans porte de sortie serait une régression : **`BOB_DEBUG=1`** installe désormais un vrai handler. Bénéfice secondaire, il rend visibles les 23 `logger.debug` jusque-là inatteignables — dont la trace d'échec par subprocess de `_run()`, la chose la plus utile à voir quand un check ne renvoie rien sur une distribution inconnue.

`BOB_DEBUG` est traité dans `bob/__init__.py` et non `bob/__main__.py` **à dessein** : `bob/i18n.py:46` et `bob/registry.py:40` appellent tous deux `resolve_share_dir()` à l'import, et ce helper logge des avertissements pour un `BOB_SHARE` invalide. Configurer le logging dans `main()` s'exécuterait après que ces enregistrements ont été émis et perdus. Vérifié :

```
$ BOB_DEBUG=1 BOB_SHARE=/nonexistent/nope bob --version
WARNING bob._paths: BOB_SHARE could not be resolved, ignoring: '/nonexistent/nope' (...)
```

### ⚡ `--check` / `--skip` ne faisaient gagner aucun temps — les snapshots précédaient le gate

`bob/runner.py` construit le snapshot de chaque section **au site d'appel** :

```python
rootkit_snapshot = RootkitSnapshot.from_system()   # toujours exécuté
_sec("rootkit", rootkit_snapshot, check_rootkit)   # gate consulté ici — trop tard
```

`_sec` vérifie `_section_enabled` en premier, donc une section filtrée ne produisait aucun finding — mais les subprocess avaient déjà tourné. Le filtrage était donc sans effet sur la *sortie* comme sur le *temps* :

```
sudo bob --quiet              5,42 s
sudo bob --quiet --check=ssh  5,40 s
```

`_sec` accepte désormais soit un snapshot pré-construit, soit une **factory sans argument**, et déballe la factory *après* le gate `_section_enabled` et *avant* `skip_if` — préservant exactement le contrat d'ordonnancement existant. Comme une section filtrée retournait déjà avant `engine.apply()`, le delta comportemental est nul **par construction**, pas par espoir.

Le motif n'est pas inventé ici : `IptablesNftSnapshot` à `runner.py:471` a toujours été collecté à l'intérieur de son garde. On généralise.

Une analyse statique des 48 snapshots de `runner.py` les a classés avant toute modification :

| Catégorie | Nombre | Traitement |
|---|---:|---|
| Référencés uniquement par leur propre `_sec` | 34 | Lazy sans risque |
| Croisés avec la logique always-on (`fw_status`, `ports_snapshot`, `net_snapshot`, `stack_snapshot`, `ddns_snapshot`, `logs_snapshot`, `docker_snapshot`, `virt_snapshot`, `snapshots`, `ipt_snapshot`) | 10 | Doivent rester eager |
| Retournés dans `ChecksResult` et consommés par `json_output` (`hardening_snapshot`, `ipv6_snapshot`) | 2 | **Doivent rester eager** |

La dernière ligne est le piège. Les deux alimentent le bloc `sysctl` de `--json-full` ; ils sont déjà typés `| None` avec un garde, donc les rendre lazy ne planterait pas — cela **retirerait silencieusement un bloc de la sortie schema v3** sous `--check=ssh --json-full`. Ils sont exclus.

Cette version convertit les cinq plus coûteux des 34 (~2,9 s d'un audit de 5,4 s) :

```
1491 ms  updates            660 ms  services_health
 324 ms  socket_units       288 ms  disk
 186 ms  systemd_hardening
```

**Résultat : `--check=ssh` 5,40 s → 2,57 s (−52 %)**, audit complet inchangé. Les 29 sites restants sont reportés à v0.13.4, en attente de retour terrain sur ces cinq.

**Sur la façon de tester cela correctement.** Un diff JSON brut n'est **pas** un contrôle d'équivalence valide : la donnée vivante (compteurs de blocage UFW) dérive entre deux runs et produit des faux positifs — la première comparaison tentée ici a signalé une différence qu'un run de contrôle du code non modifié contre lui-même a reproduite. Le test valide compare la **signature structurelle** `(clé, niveau, nature)` de chaque finding, en A/B/A/B pour annuler la dérive temporelle. Identique sur `--check=ssh`, `--skip=updates,disk`, `-p desktop` et `--check=updates` (ce dernier exerçant le chemin lazy *pris*), avec `score` / `risk` / `alert_count` / `warning_count` / `info_count` concordants et un jeu de clés JSON inchangé.

### `NO_COLOR` est honorée

`init()` de [bob/output.py](../bob/output.py) consulte désormais aussi la variable d'environnement [no-color.org](https://no-color.org), avec la sémantique conforme : toute valeur **non vide** désactive la couleur, une valeur **vide** est ignorée. Strictement additif — ce chemin ne peut que *désactiver* la couleur.

Le constat associé n'est **pas** corrigé ici : BOB émet toujours de l'ANSI quand stdout est un pipe (`bob --breakdown > fichier.txt` écrit des codes d'échappement), et `output.supports_color()` — écrite, correcte, jamais appelée — est exactement le câblage manquant. L'activer est **BREAKING** (cela retirerait la couleur de `bob | less -R`), donc cela part en v0.14.0 avec une échappatoire `FORCE_COLOR`.

### Les compteurs documentés avaient dérivé — l'un de six versions mineures

| Compteur | La doc disait | Le code dit |
|---|---:|---:|
| Règles de corrélation | 5 | **6** |
| Clés `--explain` | 116 | **169** |
| Groupes explain | 29 | **45** préfixes |
| Sections du runner | 29 | **38** filtrables + **10** always-on |
| Clés de locale | 1401 | **2008** |

`SNAPSHOT.md` était correct partout ; `README_TECH.md` avait une dérive ; `README_DEV.md` / `README_DEV_FR.md` portaient les cinq — son « 116 clés / 29 groupes » est antérieur à la baseline v0.7.0 elle-même (117/30). L'énumération des règles de corrélation omettait aussi une règle entière (`corr.stale_unmonitored` — mises à jour de sécurité en attente + aucune protection anti-brute-force).

La cause structurelle : les gardes existants (`test_doc_version_consistency.py`, `test_v0111_doc_accuracy.py`) épinglent les *versions*, les *profils* et les *options retirées* — jamais les *compteurs*. [tests/test_v0133_release.py](../tests/test_v0133_release.py) ferme la classe, en confrontant les affirmations documentées à des valeurs calculées depuis le code au moment du test.

Il **ignore délibérément les lignes qui racontent des versions passées**. `README_TECH.md:776` dit *« Baseline history: v0.7.0 audit = 117 keys / 30 prefixes »* — légitimement historique, et un garde naïf exigerait de le réécrire au chiffre du jour. Exactement une ligne du corpus a besoin de cette exemption, donc la règle reste étroite et auditable.

### Barrière de lint orientée correction, à zéro

Nouveau `.ruff.toml` et job CI exécutant `ruff check bob/`, restreint à `E9` / `F` / `B` avec **aucune règle de style** — ni longueur de ligne, ni tri d'imports, ni nommage, ni pyupgrade. Les activer sur ~33 kLoC produirait des centaines de diffs cosmétiques pour aucun défaut trouvé, soit la churn que ce projet refuse.

Limité à `bob/`. `tests/` porte ~140 findings, presque tous des imports inutilisés dans des fichiers de test : valeur nulle, et assez de bruit pour noyer le signal.

La justification a été **testée, pas supposée**. En reconstruisant le bug v0.8.3 parti sur PyPI (un `from bob.config import UserConfig` dans une branche non prise, rendant le nom local à toute la fonction et levant `UnboundLocalError`), ruff signale *« redefinition of unused 'UserConfig' from line 1 »* à la bonne ligne. Il nomme le shadowing, pas l'erreur — un indice fort plutôt qu'un diagnostic — et il n'est visible que si la base est à zéro.

`B904` (`raise ... from`) et `B905` (`zip(strict=)`) sont **reportés, pas graciés**, et la config le dit : leurs corrections changent le chaînage d'exceptions et la strictness d'itération, ce qui n'a pas sa place dans un patch. Ce sont des candidats v0.14.0.

Nettoyage pour atteindre zéro : 6 imports réellement morts, 8 préfixes `f` redondants (contenu des chaînes inchangé), et un résultat d'`ast.parse` jeté rendu explicite.

**Un retrait était faux et la suite de tests l'a rattrapé.** Retirer l'import « inutilisé » `_run` de `bob/checks/clamav.py` a cassé trois tests : ils le patchent avec `monkeypatch.setattr(clamav_mod, "_run", ...)`, ce qui exige que le nom existe dans l'espace de noms du module. Le même import dans `backup.py` et `log_rotation.py` est le même genre de **point d'injection de test**. Les trois ont été restaurés et annotés. Un grep sur les imports ne pouvait pas trouver cela — seule l'exécution de la suite le pouvait.

### Tests

6511 → **6533** (+22, tous dans `tests/test_v0133_release.py` : 6 logging, 4 snapshots lazy, 4 `NO_COLOR`, 8 compteurs de doc). 0 régression.

**v0.12.x reste EOL** ; v0.13.x est la seule ligne supportée. Mise à jour : `pipx upgrade bodyguard-of-bits` — aucune action de migration.

---

## [v0.13.2] — 21-06-2026

**Patch same-day cohérence / sécurité des commandes de finding. Additif, non-BREAKING, sans changement de score.**

Un utilisateur a remarqué que le nettoyage des noyaux obsolètes affichait un `apt purge` destructif sous le label « Vérifier : » (ℹ) — sémantiquement une action portant un label de vérification. Ça a déclenché une **passe de cohérence sémantique par sub-agent** sur chaque finding (~144 avec une `cmd`, ~170 au total), vérifiant cinq dimensions : cmd_type (action-vs-lecture), level-vs-sévérité, cohérence de nature, cohérence message↔detail↔cmd, et parité de sens EN/FR. Elle a retourné un petit groupe réel — tous des défauts de *présentation*, aucun n'affectant les scores — corrigés ici.

### 🔴 docker `userns_not_configured` — écrasement silencieux de `daemon.json`

[bob/checks/docker_audit.py](../bob/checks/docker_audit.py) suggérait, en remédiation INFO :

```
echo '{"userns-remap": "default"}' | sudo tee /etc/docker/daemon.json && sudo systemctl restart docker
```

`tee` sans `-a` **tronque et remplace tout le fichier** — un hôte qui a déjà un `/etc/docker/daemon.json` (log-driver, registry-mirrors, iptables, address-pools, …) perd tout, ne gardant que `userns-remap`, puis docker redémarre. Le detail n'en disait rien. Même classe que le déclencheur apt-purge mais pire : **perte de données** silencieuse derrière un libellé rassurant, présentée comme un fix impératif `→`. C'était le seul `tee` du code visant une config *partagée et pré-remplie* (les `tee` auditd/memory visent des fichiers dédiés mono-usage — sûrs). Corrigé : la commande est désormais **création-si-absent uniquement** —

```
test -f /etc/docker/daemon.json || { echo '{"userns-remap": "default"}' | sudo tee /etc/docker/daemon.json && sudo systemctl restart docker; }
```

— elle ne touche jamais un fichier existant (la branche `||` est sautée), ne contient **aucun texte en langage humain** (qui fuiterait une locale dans l'audit de l'autre langue, la classe reverse-i18n de v0.11.1), et le `detail` (EN+FR) dit maintenant explicitement : si `daemon.json` existe déjà, ne pas écraser — sauvegarder et fusionner la clé.

### kernel `kernels_obsolete` — `apt purge` re-typé de check vers fix

[bob/checks/kernel_modules.py](../bob/checks/kernel_modules.py) émettait la commande `apt purge linux-image-…` sous `cmd_type="check"`, dont le contrat documenté = *commandes de diagnostic lecture-seule sans changement* (rendu « ℹ » sous « Vérifier : »). Un purge est une **action** corrective, donc il utilise maintenant `cmd_type="fix"` → il s'affiche sous « Que faire ? → » où il a sa place. La précaution « purger seulement après avoir confirmé que la machine démarre sur le noyau courant » était déjà dans le detail et y reste. C'est exactement le point signalé par l'utilisateur.

### kernel `kernels_update_available` — `cmd_type="action"` invalide

La suggestion « apt upgrade » utilisait `cmd_type="action"` — **pas une valeur valide** (seulement "fix"/"check" ; « action » est une valeur de *nature*). Le renderer traite toute chaîne ≠ "check" comme la branche fix, donc ça s'affichait correctement *par accident*. Corrigé en `"fix"`.

### Garde-fou contrat dans `CheckResult.add_finding`

[bob/scoring.py](../bob/scoring.py) lève maintenant `ValueError` sur tout `cmd_type` hors `("fix","check")`. cmd_type est toujours un littéral dans les checks de BOB, donc ça ne trip qu'une erreur développeur — attrapée immédiatement par la suite de tests — et rend impossible la classe de drift-de-label silencieux (comment le typo `"action"` était passé inaperçu). Aurait attrapé le #3 à l'écriture.

### Résultats de l'audit & négatifs

La passe a confirmé que ce sont les seuls bugs de présentation : tous les autres `cmd_type="check"` sont de vraies lectures (`smartctl -a`, `stat`, `grep`, `iptables -L`, `docker inspect`, `ls`, `fail2ban-client status`) ; toutes les commandes `cmd_type="fix"` sont de vraies actions ; EN/FR sans divergence de sens ; les checks kernel-hardening / runtime INFO-only sont de la calibration délibérée, pas des mismatches. Deux items en zone grise laissés pour la passe UX v0.14.0 (le menu diagnostic `disk.smart_tips` mélangeant `smartctl -t`/`-X` et des lectures ; le `firewall_rules.orphan_rule` INFO portant un `ufw delete`).

### Tests & compatibilité

Compte de sections inchangé à **38**. **Tests** 6504 → **6511** (+7 : 3 garde-fou cmd_type + 3 docker non-clobbant dans `tests/test_v0132_cmd_semantics.py`, 1 cmd_type kernel dans `tests/test_kernel_modules.py` ; le test obsolete-kernel passé d'assertion "check" à "fix"). 0 régression. Validé live EN+FR : le purge kernel s'affiche sous « → Que faire ? », et aucune commande destructive ne reste sous « Vérifier : ».

**v0.12.x reste EOL** ; v0.13.x est la seule ligne supportée.

**Upgrade** (`pipx upgrade bodyguard-of-bits`) — seuls le libellé et le placement des commandes de remédiation changent ; aucun score, champ JSON ou code de sortie n'est affecté.

---

## [v0.13.1] — 21-06-2026

**Premier patch hardening v0.13.x — checks de contexte runtime additifs. INFO-only, non-BREAKING, sans changement de score.**

Poursuit le virage runtime ouvert par v0.13.0, en restant strictement in-branch : tout est **additif et sans déduction**. Les dents — déductions « choix opérateur » pour un conteneur privilégié et parité de scoring nftables — sont délibérément gardées pour le **bundle BREAKING planifié v0.14.0**, pour qu'un seul changement de note tombe d'un coup et non au compte-gouttes. Chaque nouvelle ligne INFO est un *finding latent* (règle anti-dashboard : elle porte un fix actionnable, sinon elle ne sort pas).

### Unités socket systemd orphelines / en échec

[bob/checks/socket_units.py](../bob/checks/socket_units.py) — nouvelle section `socket_units`, à l'intersection systemd × sockets en écoute ouverte par v0.13.0. Un service activé par socket est normal ; ce qui ne l'est pas, c'est une unité `.socket` encore **active** alors que le `.service` censé traiter les connexions est **cassé** — absent (`masked` / `not-found`) ou présent mais crashé (`ActiveState=failed`) — ou la socket elle-même en état **failed** : une socket en écoute sans consommateur fonctionnel, typiquement le résidu d'un paquet supprimé/renommé ou une unité mal configurée. Le check :

- énumère les unités `.socket` via `systemctl list-units --type=socket --all`, en résolvant `ActiveState`, les adresses `Listen`, et **tous** les services `Triggers` plus le `LoadState` *et* l'`ActiveState` de chacun ;
- flague une unité comme **orpheline** quand **au moins un** trigger déclaré est cassé — `LoadState` dans `not-found` / `masked` / `error` / `bad-setting`, *ou* `ActiveState=failed` (un service qui existe mais crashe au démarrage — la première version v0.13.1 ne regardait que le `LoadState`, donc un consommateur `loaded`+`failed` était un angle mort ; fermé avant le ship après revue) ;
- considère un service backing simplement **inactive** comme sain (l'état de repos normal de l'activation par socket — le flaguer ferait faux-positif sur quasiment chaque socket saine), et flague la socket elle-même comme **en échec** sur `ActiveState=failed` ;
- marque les unités liées à une adresse **non-loopback** (`0.0.0.0` / `::` / `*` / IP publique) pour qu'une orpheline exposée réseau ressorte.

Soigneusement **sans faux positif** : une socket à `Triggers=` *vide* (internes systemd comme `systemd-coredump.socket`, `systemd-sysext.socket`, activées autrement) n'est jamais flaguée. INFO-only ; la déduction latente (une orpheline liée à une adresse non-loopback) est un candidat v0.14.0. Validé live (33 sockets saines → clean) et sur une unité réelle forcée à un trigger cassé (orpheline rendue avec le marqueur `[net]`), EN+FR.

### Contexte cloud côté hôte

[bob/checks/cloud_context.py](../bob/checks/cloud_context.py) — nouvelle section `cloud_context`, supprimée hors cloud via `skip_if=lambda s: not s.is_cloud`. **La détection est conservatrice.** Un fournisseur identifié via SMBIOS/DMI (`/sys/class/dmi/id` : Amazon EC2, Google Cloud, l'asset tag de chassis fixe d'Azure, DigitalOcean, OpenStack, Alibaba, Oracle, Hetzner, Scaleway, Vultr, Linode/Akamai) fait autorité ; la virtualisation nue (QEMU/VMware/VirtualBox) n'est **pas** du cloud. Un simple cloud-init installé n'en est **pas** non plus — Ubuntu ship cloud-init activé, donc `/var/lib/cloud/instance` existe (avec un `DataSourceNone`) sur quantité de VM Proxmox/VMware/homelab (le public historique de BOB) ; cloud-init ne compte donc comme cloud que si le service de métadonnées est **aussi** joignable on-link (le homelab le route via la gateway et est correctement exclu). Sur une instance cloud elle remonte l'exposition strictement visible depuis l'hôte :

- **joignabilité IMDS** — le service de métadonnées d'instance (`169.254.169.254`) joignable *on-link*, distingué par une route link-scoped (`dev eth0`, sans `via`) plutôt qu'une route passant par la gateway par défaut ; avec un rappel IMDSv2 (BOB ne peut pas vérifier le réglage IMDSv2 hors-ligne) ;
- **user-data persistée lisible par tous** (`/var/lib/cloud/instance/user-data.txt`), qui peut contenir des secrets de provisioning.

(Une ligne `cloud-init toujours activé` a été retirée avant le ship : cloud-init activé est le *défaut éditeur* sur les images cloud — le flaguer serait du bruit sur quasiment chaque instance, le même piège que BOB évite pour l'exposition `systemd-analyze`.) **Strictement côté hôte.** Aucune API cloud, IAM, bucket, security group, VPC ou identifiant n'est jamais touché — c'est le territoire de Scout Suite / Prowler, et y entrer dissoudrait la singularité mono-hôte et zéro-dépendance de BOB. INFO-only ; les déductions IMDS-sans-IMDSv2 et user-data-lisible-par-tous sont des candidats v0.14.0. Path négatif validé live sur un hôte non-cloud (section supprimée, score inchangé) ; path positif rendu end-to-end EN+FR sur une instance Amazon EC2 forgée.

### Fixes robustesse — `ddns` + `ssh` (chemin `/root` illisible)

Même classe, deux checks : un chemin sous un répertoire que l'auditeur ne peut pas **parcourir** (un `/root` durci, ou un user namespace où root mappe sur un uid non privilégié) fait lever `PermissionError` à `Path.exists()` / `is_dir()` / `is_symlink()` (EACCES n'est pas avalé par pathlib).

- [bob/checks/ddns.py](../bob/checks/ddns.py) — `Path.exists()` et `_is_safe_config_path()` (via `is_symlink()`) levaient *hors* du try/except existant, **avortant tout l'audit**. Le nouveau helper `_config_present()` enveloppe la sonde existence + sûreté et **dégrade un chemin illisible en « absent »**. Observé pour la première fois pendant la validation userns de v0.13.0 ; le test de régression reproduit le vrai `EACCES` avec un répertoire mode-`000`.
- [bob/checks/ssh/_snapshot.py](../bob/checks/ssh/_snapshot.py) — révélé par le **field test live** de v0.13.1 : `~/.ssh` sous un home non-parcourable (`/root/.ssh` dans un user namespace) faisait lever `is_dir()` ; le runner l'attrapait mais **fuitait la chaîne `[Errno 13] …/.ssh` dans le rapport**. Toute la sonde `~/.ssh` côté utilisateur est maintenant enveloppée dans `try/except OSError`, dégradant en « pas de `~/.ssh` » (même principe que `_config_present`). Pré-existant (pas une régression v0.13.1), userns-only, cosmétique — corrigé par cohérence une fois exposé par le field test. Test de régression dans `TestSshDir` (skippé en root).

(Ce sont les deux premiers du backlog « sweep `except OSError` » ; les autres checks ont été vérifiés sans fuite sous le même run userns.)

### Tests & compatibilité

Compte de sections **36 → 38**. **Tests** 6461 → **6504** (+43 : 21 dans `tests/test_socket_units.py`, 18 dans `tests/test_cloud_context.py`, 3 dans `tests/test_ddns.py`, 1 dans `tests/test_ssh.py`). 0 régression, vert en ordre déterministe et aléatoire. Parité locale EN/FR préservée.

**v0.12.x reste EOL** ; v0.13.x est la seule ligne supportée (un patch ne change pas le tableau EOL).

**Upgrade** (`pipx upgrade bodyguard-of-bits`) — **entièrement rétro-compatible** : trois ajouts INFO-only ; aucun champ de sortie, clé JSON, score ou code de sortie existant ne change. La section cloud n'apparaît que sur une instance cloud.

---

## [v0.13.0] — 20-06-2026

**Première release v0.13.x — extension de scope. Deux nouveaux checks INFO-only. Additif, non-BREAKING, sans changement de score.**

Après un long cycle de durcissement interne (v0.5.x–v0.12.x), v0.13.0 est la **première vraie croissance de couverture** de BOB — exploitant deux surfaces documentées, déterministes, offline-safe que rien n'utilisait : la métrique d'exposition par service de systemd, et la posture d'isolation propre d'un conteneur. Les deux sont conçus conservativement (INFO-only, aucune déduction) pour pouvoir shipper *sans* signal terrain, laissant la calibration du scoring pour plus tard.

### Durcissement des services — `systemd-analyze security`

[bob/checks/systemd_hardening.py](../bob/checks/systemd_hardening.py) lance `systemd-analyze security --json=short` restreint aux services **en cours** (intersection avec `systemctl list-units --state=running`) et remonte : un résumé (compte par prédicat UNSAFE/EXPOSED/OK), les services en cours les moins durcis (top 5), et un pointeur `systemd-analyze security <unit>`. **Aucune déduction, par design** : systemd ship la grande majorité des units non-durcies — c'est l'*état normal par défaut* d'un hôte Linux, pas une mauvaise config choisie, et la doc systemd qualifie le score d'exposition de guide *relatif*, explicitement pas un verdict de vulnérabilité. Déduire dessus serait du bruit sur chaque machine et violerait le cadrage A1/A2. Une déduction étroite défendable (unit *écrite par l'admin* dans `/etc/systemd/system` à exposition UNSAFE) est différée au signal terrain. Nouvelle section `systemd_hardening` (groupe SYSTEM HARDENING, domaine hardening). Field-testé live EN+FR (44 services évalués, score inchangé).

### Posture de sécurité du conteneur

[bob/checks/container_security.py](../bob/checks/container_security.py) ne s'exécute que **dans un conteneur** (section supprimée sur un hôte normal via `skip_if`). Détection : `systemd-detect-virt`, `/.dockerenv`, `/run/.containerenv`, `/proc/1/cgroup`. Lectures (interfaces noyau documentées, offline) : **capabilities** (`/proc/self/status` CapBnd → détection privilégié/CAP_SYS_ADMIN + liste des caps dangereuses, bitmask parsé en interne sans `capsh`), **seccomp**, **user namespace** (`/proc/self/uid_map` ; un map non-identité = root du conteneur ≠ root de l'hôte, donc le warning « root » est correctement supprimé), **rootfs en écriture** (`/proc/mounts`). INFO-only dans cette première version — une vraie déduction WARN pour un conteneur privilégié est le fast-follow évident une fois le signal runtime accumulé. Nouvelle section `container_security` (groupe SYSTEM HARDENING, domaine hardening).

### Validation

Le check systemd a tourné live sur un hôte réel, EN+FR. Le check conteneur — qui par définition ne peut pas s'exécuter sur un hôte non-conteneur — a été validé contre de **vraies données noyau `/proc` dans des user namespaces Linux** via `unshare` : contexte privilégié (CapBnd full → privilégié + toutes caps dangereuses), non-privilégié (`setpriv` drop → `caps_restricted`), seccomp désactivé, et la branche subtile **userns-actif** (root présent mais uid_map non-identité → warning root-hôte correctement *non* émis) tous confirmés sur du réel, et la section complète rendue end-to-end EN+FR dans le namespace. (Aucun runtime conteneur requis — `unshare` exerce les mêmes primitives noyau. Aparté robustesse sous le mapping userns artificiel : un check `ddns` sans rapport a levé une `PermissionError` non catchée sur un fichier `/root` illisible et a aborté le run — artefact du userns, pas une réalité conteneur ; noté comme edge pré-existant pour une future passe.)

### Tests, EOL & compatibilité

Compte de sections **35 → 36**. **Tests** 6442 → **6461** (+19 : 7 systemd + 12 conteneur). 0 régression.

**Fin de vie** : selon la politique « patchs pour la ligne minor la plus récente uniquement », **v0.12.x est maintenant déclarée EOL** au ship de v0.13.0 ; les lignes v0.8.x–v0.11.x sont également EOL ; **v0.13.x est la seule ligne supportée**. v0.7.x reste EOL (v0.8.1), v0.6.x reste EOL (v0.7.2). SECURITY.md / SECURITY_FR.md mis à jour.

**Upgrade** (`pipx upgrade bodyguard-of-bits`) — **entièrement rétro-compatible** : deux sections INFO-only ajoutées ; aucun champ de sortie, clé JSON, score ou code de sortie existant ne change. La section conteneur n'apparaît que dans un conteneur.

---

## [v0.12.2] — 12-06-2026

**Cleanup hardening de clôture de branche — une passe deep-audit du tool entier + un sweep "angles inexplorés" avant de sceller la ligne v0.12.x. Aucun changement de comportement.**

Après la campagne d'audit v0.12.1 (naive + 4 tours advanced sur les changements récents), un audit deep hardening par sub-agent a balayé le code **plus large, moins récemment touché**, et un sweep de suivi a sondé des angles que rien n'avait vérifiés (injection Markdown, génération cron, en-têtes email, parsing de profils). Verdict : **CLOSE THE BRANCH** — 0 critique, 0 important. Deux petits items corrigés pour sceller propre ; tout le reste vérifié solide.

### M-1 — `_DOMAIN_SECTIONS` contenait des préfixes de clés, pas des noms de sections réels

`bob/domain_scores.py` construit `_DOMAIN_SECTIONS` (domaine → sections contributrices) depuis `_PREFIX_TO_DOMAIN`, puis passe ces noms à `runner._section_enabled` dans `domain_inactive_reason` pour décider si un domaine est *skippé par le profil*. La plupart des préfixes de clés égalent le nom de section, mais deux non — `virt` (section réelle `virtualization`) et `logs` (section réelle `ufw_logging`). Comme les deux sections réelles sont **always-on** (jamais filtrables/skippables), le domaine hardening est toujours actif et l'écart était **inatteignable** — mais le gate testait des noms inexistants et le commentaire prétendait à tort que les préfixes *étaient* des noms de sections. Corrigé avec un petit remap `_PREFIX_TO_SECTION`, pinné par un nouveau garde de drift (`tests/test_v0122_branch_close.py`) qui asserte que **chaque** nom dans `_DOMAIN_SECTIONS` est une vraie entrée `runner._SECTIONS`.

### Nom de cron — défense-en-profondeur sur l'écriture cron root

`bob/cron/_install.py` slugue le nom pour le chemin (`/etc/cron.d/bob-<slug>` — pas de traversal) mais écrit le nom **brut** dans le commentaire `# name:` du fichier cron root généré. L'audit a signalé qu'un newline dans le nom injecterait une 2e ligne. Vérification faite, **ce n'est PAS une injection exploitable** : le nom vient de `prompt_wizard` → `input(label).strip()`, et `input()` est line-based, donc un nom saisi interactivement ne peut pas contenir de newline. Rapporté honnêtement comme défense-en-profondeur, pas un bug live. Mais worth doing : un outil de hardening ne doit pas dépendre de la sémantique line de `input()` comme *seule* garde pour une écriture cron root — les caractères de contrôle sont maintenant strippés du nom avant le commentaire, rendant l'injection impossible quelle que soit la source. Cohérent avec `_validate_custom_cron` déjà strict. La ligne email était déjà sûre (`_EMAIL_RE` anchored).

### Vérifié propre (enregistré pour le prochain auditeur)

`_atomic.py` (mkstemp + fchmod + fsync + cleanup sur erreur) · `webhook.py` (http/https-only + redaction credentials + timeout fini, pas de SSRF) · subprocess (pas de `shell=True`, `LC_ALL=C`, garde symlink `authorized_keys → /etc/shadow`) · `fixes.py` (cmd author-controlled + rejet shell-metachar) · parsers logs/config (regex anchored, pas de ReDoS) · i18n (1975/1975 parité) · pas de drift de littéral · parser profils `.conf` (extends borné à 8 + fallback) · export Markdown (`_md_escape` échappe `|` et `\n` ; `*`/backtick non échappés = NIT cosmétique sur strings author-controlled).

### Tests & compatibilité

**Tests** 6437 → **6442** (+5). 0 régression, vert déterministe + aléatoire. **v0.7.x reste EOL** (v0.8.1) ; **v0.6.x reste EOL** (v0.7.2). Cette release **clôt la branche v0.12.x**. Upgrade : `pipx upgrade bodyguard-of-bits` — aucun changement de comportement.

---

## [v0.12.1] — 12-06-2026

**Premier patch hardening v0.12.x — complétude de l'affichage des domaines + campagne d'audit naive/advanced. Additif et entièrement rétro-compatible.**

Le changement principal implémente la demande différée de v0.12.0 : **toujours afficher les 7 domaines de score, même inactifs, avec la raison précise** de leur non-scoring. Les domaines inactifs ne sont jamais comptés dans la moyenne — les scores, le cap F1 "10 = sans défaut" et la garde anti-inversion v0.4.5 sont tous préservés. Le changement a ensuite déclenché une campagne d'audit profonde (un tour naive-user + quatre tours advanced-user) qui a trouvé et corrigé une série de problèmes (CLI, contrat de scoring, sorties machine, permissions de fichiers).

### Afficher tous les domaines, avec la raison (texte + JSON + Markdown + HTML)

`bob.domain_scores.domain_inactive_reason()` classe pourquoi un domaine n'a produit aucun finding actionnable (OK/WARN/ALERT), via une source unique partagée par tous les renderers :

| `reason` | Signification |
|---|---|
| `info_only` | Les checks ont tourné et rapporté, mais seulement de l'informatif. |
| `profile_skipped` | Le profil actif saute toutes les sections du domaine (ex. `disk` en `container`). |
| `filtered` | Exclu par un filtre `--check` / `--skip` ce run. |
| `not_installed` | Les checks ont tourné et trouvé le composant absent. |

La précédence est INFO-only → a tourné-mais-vide (`not_installed`) → filtré → skippé-par-profil, calculée via le gate `_section_enabled` du runner pour coller exactement à ce qui a tourné. **`disk` n'est jamais "non installé" à tort** : sur un host réel il est actif (findings SMART) ; seul un profil qui le saute donne `profile_skipped`. L'affichage texte ([bob/domain_scores.py](../bob/domain_scores.py) `render_domain_scores`) montre les domaines inactifs grisés avec la raison ; la même donnée est exposée en JSON, Markdown et HTML (voir ADV-1 / ADV-B1).

### Tour naive-user — A / B / C / E

- **A — `--check`/`--skip` étiquetaient mal les domaines filtrés.** `bob --check=ssh` montrait `Samba / Files & Access / Updates : not installed` — faux (filtrés, pas absents). `domain_inactive_reason` consomme maintenant la config et le gate `_section_enabled`, renvoyant la nouvelle raison `filtered`.
- **B — `--profile=typo` corrompait la config sauvegardée.** [bob/__main__.py](../bob/__main__.py) persistait *n'importe quelle* valeur `--profile` (via `set_profile`) **avant** de la valider, donc `--profile=banane` écrivait `audit_profile=banane` et chaque run suivant tombait en fallback, perdant silencieusement le vrai profil. Maintenant le profil est résolu d'abord et seul un nom **valide** est persisté.
- **C — le root-gate passait avant la validation de `--profile`.** `bob --profile=typo` sans sudo affichait *"must be run as root"* au lieu de signaler le mauvais profil. Un `--profile` inconnu est maintenant signalé **avant** `require_root()` (comme l'ordre F6 pour `--check`/`--skip`). `--diff` / `--html` nécessitent légitimement root et sont inchangés.
- **E — polish CLI.** Ajout de `--english` (symétrie avec `--french`). `--output` accepte maintenant `html` et `json-full` → alias **complet** de `--format` (les deux étaient rejetés avant). Les tokens `--check`/`--skip`, les clés `--explain` et les valeurs `--output`/`--format` sont maintenant **casse-insensibles**. Help + complétion bash mis à jour.

### Tours advanced-user — ADV-1 / ADV-D2 / ADV-G2 / ADV-B1

- **ADV-1 — le JSON ne permettait pas de reproduire le score.** `domain_scores` exposait les 7 domaines à leur score sans marqueur actif/inactif, donc un consommateur qui les moyennait obtenait 10 alors que le vrai headline était 9, et ne pouvait pas distinguer un `samba` absent (montré 10) d'un vrai 10. Chaque `domain_scores[d]` porte maintenant **`active` (bool)** et **`reason` (code stable, ou `null` si actif)**. **Additif en schema v3 — pas de bump** ([bob/json_output.py](../bob/json_output.py)).
- **ADV-D2 — `--output` était un alias incomplet.** `--format=json-full` marchait mais `--output=json-full` erreur. Corrigé (intégré à E).
- **ADV-G2 — `history.jsonl` pouvait rester world-readable.** I-5 (v0.6.1) mettait `0600` seulement à la *création* ; un fichier legacy créé avant restait `0644`. Le chemin append fait maintenant un `os.chmod` à `0600` à chaque write — un outil de hardening ne doit pas fuiter son propre état ([bob/history.py](../bob/history.py)).
- **ADV-B1 — les rapports Markdown + HTML n'avaient pas le breakdown par domaine** (texte + JSON l'avaient). Les deux rendent maintenant la table par domaine (score + statut), EN+FR, via le helper format-agnostique partagé `domain_rows()`.

### Vérifié propre (résultats négatifs de l'audit)

Déterminisme (JSON bit-identique entre runs), maths de scoring (cap domaine firewall-inactif × F1 × escalade posture), concurrence (deux runs parallèles laissent `last_baseline.json` / `history.jsonl` non-corrompus), rendu `LC_ALL=C` (stdout UTF-8, pas d'erreur d'encodage), lignes reason en `--no-color`, interaction `--ignore` (un finding ignoré garde son domaine actif et recalcule proprement), et import standalone de `build_json_data` (pas de cycle) — tous sondés et corrects.

### Tensions de design connues (laissées telles quelles, documentées)

`--check=X` produit un score d'audit partiel non comparable au baseline complet — pré-existant, déféré. JSON utilise `alert_count`/`warning_count` alors que CSV/webhook gardent `alerts`/`warnings` — décision F9 (contrats séparés) assumée. Le résidu `ignore:` vide laissé par `--unignore` de la dernière clé est de la préservation délibérée des commentaires opérateur.

### Tests & compatibilité

**Tests** 6401 → **6437** (+36). 0 régression, vert en ordre déterministe et aléatoire. Field test bilingue complet sur host réel (texte / Markdown / HTML / `--json-full` × EN/FR + chaque fix CLI) propre. **v0.7.x reste EOL** (v0.8.1) ; **v0.6.x reste EOL** (v0.7.2).

**Upgrade** (`pipx upgrade bodyguard-of-bits`) — **entièrement rétro-compatible** : le changement JSON est additif (nouvelles clés `active`/`reason`, schema_version toujours `"3"`), les nouveaux flags CLI sont additifs, aucun champ existant ne change de sens.

---

## [v0.12.0] — 11-06-2026

**Première release v0.12.x — bundle UX BREAKING planifié (F1 / F2 / F4 / F6 / F9).**

Les cinq findings du test bilingue approfondi en live de v0.11.x qui ne pouvaient pas rider un patch parce que chacun change un contrat, un code de sortie, ou le score. Le scope a été figé avant impl (le pattern "planned BREAKING bundle" validé en v0.9.0 et v0.11.0), les questions de design ont été tranchées avec le mainteneur (stratégie de cap F1 ; versioning de schéma F9), et un audit pre-ship sub-agent a tourné avant le tag.

### F1 — le modèle de score effaçait les déductions (BREAKING, score)

Le score de sécurité de tête est la **moyenne des scores de domaine actifs** ([bob/domain_scores.py](../bob/domain_scores.py) `compute_global_from_domains`), pas la somme brute des déductions. La moyenne équipondérée est délibérée (elle empêche un domaine bruyant de dominer le chiffre), mais l'arrondir **vers le haut** pouvait effacer une vraie déduction : une machine dont le seul souci était une mise à jour firmware en attente scorait brut 9/10, pourtant la moyenne `(6×10 + 1×9) / 7 = 9.857` **arrondissait à 10/10**. Le résultat se lisait comme un audit parfait alors que le même rapport affichait `✖ Action requise`, 5 avertissements et "Des corrections sont nécessaires" — le bug de qualité-perçue le plus érodant de la confiance dans l'outil.

**Fix — "10/10 = audit sans défaut".** Dès qu'une déduction a été appliquée (`engine.raw_score < MAX_SCORE`), le score de tête est plafonné à `MAX_SCORE − 1` (9/10) ; un 10 parfait est désormais réservé à un audit sans rien à corriger. Les moyennes plus basses ne sont pas affectées (elles arrondissent déjà sous 9). Mécanique :

- [bob/scoring.py](../bob/scoring.py) — `ScoreEngine.set_global_score(score, precap=None)` enregistre la moyenne avant cap dans `_global_precap` ; nouvelle propriété `domain_average_precap` qui l'expose.
- [bob/domain_scores.py](../bob/domain_scores.py) — `apply_domain_score_override` calcule la moyenne, la stocke comme `precap`, puis applique le cap.
- [bob/breakdown.py](../bob/breakdown.py) — `--breakdown` imprime maintenant la moyenne des domaines et le cap en **deux étapes distinctes** (`Moyenne des domaines : 10/10` → `Déduction présente → score de tête plafonné à 9/10`) au lieu d'un chiffre opaque. Nouvelle clé locale `breakdown.f1_cap` (EN+FR).
- Le champ `score` JSON reflète la valeur plafonnée (la conséquence wire-format notée dans le plan).

**BREAKING :** toute machine avec au moins une déduction qui affichait 10/10 affiche maintenant 9/10, et `--target 10` sur une telle machine retourne le code 4. Pinné par [tests/test_v0120_score_model.py](../tests/test_v0120_score_model.py) (le cap se déclenche sur déduction, un audit clean garde 10, le cap ne remonte jamais un score, precap enregistré).

### F2 — incohérence sévérité corps↔résumé (présentation)

Le bloc résumé groupe les findings par **nature** (Action requise / Améliorations possibles) et, avant le fix, imposait le symbole de la section à chaque item en dessous (`✖` pour toute "Action requise", `⚠` pour toute "Amélioration possible"). Le corps imprime chaque finding par sa **sévérité**. Donc un item action de niveau WARN comme `firmware.fwupd_updates` affichait `⚠ [WARNING]` au corps mais `✖` au résumé — un finding portant deux symboles de sévérité. [bob/display.py](../bob/display.py) `_summary_findings_lines` dérive maintenant le symbole par item de `item.level` (`⚠` WARN / `✖` ALERT) pour que le résumé s'accorde avec le corps ; l'**en-tête** de section groupe toujours par nature (quoi faire). Pinné par [tests/test_v0120_ux_bundle.py](../tests/test_v0120_ux_bundle.py) `TestF2SeverityBullet`.

### F4 — `--explain <clé-inconnue>` sortait 0 (BREAKING, code de sortie)

`bob --explain foo.bar` pour une typo ou une clé inexistante affichait un message "clé inconnue" mais retournait **0**, indistinct d'une explication réussie — or les codes de sortie de BOB sont une API publique stable. [bob/explain.py](../bob/explain.py) `run_explain` retourne maintenant un `bool` ; [bob/__main__.py](../bob/__main__.py) le mappe : une clé valide, `list` et le navigateur interactif retournent `EXIT_OK` (0) ; une clé inconnue retourne `EXIT_ERROR` (3). **Additif** (sûr isolément) : pour un quasi-match, la branche inconnue imprime une suggestion `difflib.get_close_matches(key, EXPLAIN_KEYS, cutoff=0.6)` "Vouliez-vous dire : ssh.password_auth ?" (nouvelle clé locale `explain.ui.did_you_mean`, EN+FR). Pinné par `TestF4ExplainExitAndSuggestion` (retours bool sur chaque chemin, suggestion présente pour une typo / absente pour une clé sans rapport, codes de sortie main()).

### F6 — le root-gate passait avant la validation `--check`/`--skip`

`bob --check=typo` **sans sudo** affichait *"This script must be run as root"*, forçant l'opérateur à sudo + re-run seulement pour ensuite découvrir que le token était faux. La validation des tokens `--check`/`--skip` ne nécessite aucun privilège, elle s'exécute donc maintenant **avant** le root-gate dans [bob/__main__.py](../bob/__main__.py) `_run` (le bloc `i18n.init` + `validate_check_filters` déplacé au-dessus de `require_root()`). Un `--check` tout-invalide rapporte le token inconnu et retourne `EXIT_ERROR` sans jamais demander root ; un match partiel (au moins un token valide) avertit puis procède au gate, puisqu'un vrai audit a besoin de root. Une garde AST statique fige l'ordre contre les régressions (l'`UnboundLocalError` de v0.8.3 venait de ce même scope `main()`, donc l'ordre est gardé, pas seulement testé comportementalement).

### F9 — nommage des compteurs JSON + schéma v2 → v3 (BREAKING, schéma)

Le schéma JSON v2 exposait des compteurs entiers sous `alerts` et `warnings`, alors que le compteur sibling était `info_count`. Un consommateur itérant `data["alerts"]` — attendant raisonnablement une liste, à l'image du tableau `findings` de `--json-full` — recevait un `int` et crashait avec `TypeError: 'int' object is not iterable`. [bob/json_output.py](../bob/json_output.py) les renomme en **`alert_count` / `warning_count`** par symétrie avec `info_count`.

Un renommage de clé est un changement breaking. Deux options de design étaient sur la table (un bump de schéma propre, ou des champs `*_count` additifs gardant les anciens dépréciés). La décision a suivi **la propre règle documentée du projet** (SNAPSHOT.md : *"les changements breaking incrémentent `schema_version` au majeur suivant"*) et le **précédent clean-cut** (v1 entièrement retiré en v0.9.0 F-3 — aucune déprécation gardée). Donc **schema_version passe `"2"` → `"3"`** : `DEFAULT_SCHEMA_VERSION = "3"`, `SUPPORTED_SCHEMA_VERSIONS = {"3"}`, les constantes/builder v2 deviennent v3 en place, et `build_json_data` raise `ValueError` pour toute version autre que `"3"`. Cela garde le champ `schema_version` comme un signal de compatibilité honnête pour tout changement futur, plutôt que de laisser deux formats wire différents revendiquer `"2"`.

Le **payload webhook générique garde délibérément `alerts`/`warnings`** ([bob/webhook.py](../bob/webhook.py) `build_generic_payload`) : il n'a pas d'`info_count` (donc aucune incohérence interne à corriger), il diverge déjà du schéma `--json` (`source`, `max_score`, `timestamp` vs `timestamp_utc`), et c'est un contrat plat séparé — le renommer serait une casse gratuite. Tant qu'on y était, l'exemple "Enveloppe JSON générique" d'AUTOMATION — qui **mal-documentait depuis longtemps** le payload webhook comme *"le même contrat que `bob --json`"* (montrant `schema_version`, `deductions`, `network_context` que le webhook n'envoie jamais) — a été corrigé vers la vraie forme `build_generic_payload`. Les sections JSON de README_TECH, SNAPSHOT et AUTOMATION ont été mises à jour EN+FR avec un guide de migration v1/v2 → v3 et la table de comparaison des schémas retirés.

Pinné par [tests/test_json_schema_v2.py](../tests/test_json_schema_v2.py) `TestF9CountKeyRename` (nouvelles clés présentes, anciennes absentes, trio de compteurs symétrique) + l'assertion schema-version-`"3"` + l'import de la constante de production (pour que toute drift future se déclenche immédiatement).

### Isolation de test — fuite couleur de la barre de score watch

`bob.output._c` défaut = couleurs **ON** ; les assertions `TestScoreBar` / `TestScoreBarTypes` (la barre ne contient que `█`/`░`) ne passaient que quand un test sans rapport laissait le global dans l'état couleurs-OFF. Sous ordre déterministe (et par intermittence sous `pytest-randomly`) cette fuite n'est pas garantie, donc les tests de barre échouaient avec des codes ANSI dans la string. Ils forcent maintenant le monochrome explicitement via une fixture `output.init(no_color=True)` avec teardown — un vrai fix d'isolation révélé par les runs full-suite de F1, pas introduit par lui.

### Tests & compatibilité

**Tests** 6381 → **6401** (+20 : 6 F1 + 3 F2 + 6 F4 + 2 F6 + 3 F9). 0 régression, vert en ordre déterministe et aléatoire. L'audit pre-ship sub-agent a retourné **0 critique / 0 important** côté code et SHIP, ne signalant que la drift de l'exemple JSON d'AUTOMATION.md (corrigée dans cette release). **v0.7.x reste EOL** (déclaré en v0.8.1) ; **v0.6.x reste EOL** (déclaré en v0.7.2).

**Upgrade** (`pipx upgrade bodyguard-of-bits`) — **BREAKING pour** : les consommateurs JSON (lire `alert_count`/`warning_count`, vérifier `schema_version == "3"`) ; les scripts qui branchent sur les codes de sortie `--explain` (une mauvaise clé est maintenant 3, pas 0) ; une CI gardée par `--target` sur une machine portant une déduction (le score de tête plafonne maintenant à 9). L'usage interactif n'est pas affecté au-delà du score corrigé et des symboles de résumé.

---

## [v0.11.2] — 11-06-2026

**Deuxième patch hardening v0.11.x — complétude i18n (F8 + F8b).**

Ferme les deux dernières lacunes i18n d'audit FR, toutes deux révélées par un **test bilingue approfondi en live** de v0.11.1 (audit réel sur l'host en EN et FR, comparaison ligne à ligne). Ni les audits deep code-level (locale défaut) ni la passe UX précédente (surtout EN) ne pouvaient les voir — il fallait des runs EN/FR côte à côte. Les findings UX restants (F1 modèle de score, F2 présentation sévérité, F4 exit-code explain, F6 ordre root-gate, F9 nommage JSON `alerts`/`warnings`) sont BREAKING ou des décisions de design et restent dans le bundle v0.12.0 planifié.

### F8 — les 60 lignes de référence "Best practice" étaient EN-only

[bob/data/cis_refs.json](../bob/data/cis_refs.json) mappe chaque finding key vers un `ref` (ligne de référence sous un finding en verbose + dans `--explain`). Deux types :
- **114 entrées CIS-codées** (`"code": "CIS:X.Y.Z"`) — `ref` = titre de benchmark CIS canonique.
- **60 entrées best-practice** (`"code": null`) — conseils rédigés par BOB pour les findings sans code CIS formel.

Le `ref` est lu directement du fichier data, **pas** via le système locale → les 60 lignes best-practice rendues en **anglais dans un audit FR**.

Fix — chaque entrée best-practice porte un `ref_fr`, et [bob/cis_refs.py::get_cis_ref](../bob/cis_refs.py) est devenu locale-aware : `lang` défaut sur la locale active (résolu en lazy via `i18n.current_lang()`, pas de cycle d'import) ; retourne `ref_fr` si FR + présent, sinon fallback `ref`. Les 4 call sites n'ont pas besoin de changer. Les **114 entrées CIS-codées n'ont délibérément pas de `ref_fr`** — titres CIS canoniques publiés en anglais par le Center for Internet Security ; les traduire inventerait une formulation non officielle et risquerait l'imprécision. Résultat live FR : *"Bonne pratique — S'assurer que les interfaces bridge ne contournent pas les règles UFW FORWARD"*.

### F8b — deux commentaires `cmd=` en anglais hardcodé (le fix disk.py était incomplet)

v0.11.1 avait fixé les commentaires SMART disque qui fuitaient le **français dans EN** ; un scan propre ce cycle a trouvé l'inverse : 2 suggestions `cmd=` avec commentaires inline **anglais** hardcodés fuitant dans les audits **FR** :
- [bob/checks/ipv6.py](../bob/checks/ipv6.py) : `# set IPV6=yes, then: sudo ufw reload`
- [bob/checks/log_rotation.py](../bob/checks/log_rotation.py) : `# add: SystemMaxUse=500M` (confirmé fuyant dans le run FR live)

Maintenant `f"… # {_t('…')}"` avec nouvelles clés `ipv6.cmd_comment_enable` + `log_rotation.cmd_comment_maxuse` (EN+FR). Scan complet confirmé : c'étaient les **2 seuls restants** — tous les `message`/`detail`/`reason` passent déjà par `_t()`.

### Garde anti-drift

[tests/test_v0112_i18n_refs_and_cmd_comments.py](../tests/test_v0112_i18n_refs_and_cmd_comments.py) scanne `bob/checks/` pour un littéral `cmd=` contenant `  # <texte>` hardcodé (les commentaires localisés en `# {_t(...)}` ne matchent pas). Ferme la classe de leak disk.py/ipv6/log_rotation. + 9 tests F8.

### Deux "findings" vérifiés comme NON-bugs (vérifier avant de fixer)

- **`--unignore` laisse un header `ignore:` résiduel** : délibéré (`remove_ignore_key` I-1 v0.8.1 préserve les commentaires opérateur + structure YAML verbatim). Laissé tel quel.
- **Alignement des bordures de box** : chaque ligne fait exactement 80 chars — pas de désalignement char-count. Tout offset visuel = effet de largeur d'affichage emoji (east-asian width), hors scope patch. Laissé tel quel.

### Numbers

- **Tests 6369 → 6381** (+12 : tous dans `test_v0112_i18n_refs_and_cmd_comments.py` — 9 F8 + 3 F8b). 0 régression.
- 4 fichiers production (`cis_refs.py`, `ipv6.py`, `log_rotation.py`) + 1 data (`cis_refs.json` +60 `ref_fr`) + 2 locales (+2 clés).

### Upgrade

```
pipx upgrade bodyguard-of-bits
```

Pas de migration. Les utilisateurs FR voient les 60 lignes "Best practice" et les 2 commentaires en français ; les audits EN inchangés. **v0.7.x reste EOL** (déclaré v0.8.1) ; **v0.6.x reste EOL** (v0.7.2).

### Leçons

- **Un fix est incomplet tant qu'on n'a pas scanné toute la classe.** disk.py v0.11.1 = une instance ; v0.11.2 en trouve 2 autres (sens inverse). Le garde anti-drift pin la classe entière.
- **Le test bilingue live trouve ce que le monolingue ne voit pas.** F8 et F8b invisibles en EN-only et en audit code locale-défaut.
- **Vérifier avant de fixer (encore).** 2 observations du deep test étaient correctes-by-design ; les toucher aurait régressé le contrat de préservation I-1 ou chassé un bug d'alignement inexistant.

---

## [v0.11.1] — 11-06-2026

**Premier patch hardening v0.11.x — deux minors issus de l'audit deep whole-tool post-v0.11.0.**

### L'audit

La 20e passe d'audit deep a balayé tout l'outil (pas juste le diff v0.11.0) — parsers d'input, chaque site de construction `cmd=`, le contrat atomic-write + tous les callers, l'intégrité scoring/posture/output, CLI/TUI, et i18n. Résultat : **0 critique + 0 important + 2 minor**. Après 19 passes les surfaces sensibles sont clean :

- **injection cmd** : 68 sites `cmd=` vérifiés — toute valeur config/parsée atteignant un shell est `shlex.quote`'d, int/whitelist-bounded, ou gardée par `fixes._has_shell_ops` (`subprocess.run(shlex.split(...))` sans `shell=True`). La génération de ligne cron valide les emails contre une regex ancrée.
- **atomic-write** : `_atomic.py` fsync(fd)+fsync(dir), `mkstemp` par appel, cleanup tmp sur tout path d'échec.
- **HTML output** : chaque champ de finding + hostname/OS échappé via `_h()`.
- **contrats de clés littérales** (classe de bug v0.10.2) : chaque littéral de clé dans `scoring.py`/`exposure.py`/`correlation.py` résout vers une clé live.

Le filter conservateur a sélectionné **les deux** minors : petits fixes de cohérence de contrat qui bundlent proprement, alignés sur un contrat existant.

### M-1 — i18n ne doit pas crasher sur un template locale malformé

[bob/i18n.py](../bob/i18n.py)::`t()` ne catchait que `KeyError` de `str.format()`. Mais `str.format()` lève plus que ça : une **accolade non fermée** (`"{price"`) → `ValueError` ; un **champ positionnel** (`"{0}"`) appelé avec kwargs nommés → `IndexError`. L'un ou l'autre propageait non catché et **crashait l'audit** pour la locale affectée. Le linter parity ne comparait que le *set* de placeholders `{name}` bien formés.

Fix à deux couches :

1. **Filet runtime.** `t()` dégrade vers le template brut sur `(KeyError, IndexError, ValueError)`. `try_t()` gagne le guard `(IndexError, ValueError)` **en préservant sa propagation `KeyError` intentionnelle** (un kwarg oublié est une erreur du caller que les callers distinguent ; un template malformé est de la data corrompue et dégrade).
2. **Prévention au CI (le guard le plus fort).** [tests/test_locale_coverage.py](../tests/test_locale_coverage.py)::`TestTemplateWellFormed` parse chaque string des deux locales avec `string.Formatter().parse()` et rejette les accolades non équilibrées + champs positionnels. Protège *tous* les lecteurs (`t`, `try_t`, `t_or_hardcoded`).

Les locales actuelles sont clean — classe de crash-on-future-edit latente, fermée avant qu'elle puisse mordre, cohérente avec le contrat i18n "ne crashe jamais, dégrade en bracketed-fallback".

### M-2 — `--test-webhook` honore maintenant `--offline`

[bob/__main__.py](../bob/__main__.py) : `--offline` est documenté comme désactivant **tous** les appels réseau sortants (air-gapped). Le path webhook audit-time gatait déjà dessus, mais la commande explicite `--test-webhook` non — donc `bob --test-webhook --offline` faisait quand même un POST.

L'excuse "intention explicite de test réseau" est faible : `--offline` est un override global délibéré, et quand deux flags entrent en conflit autour d'un garde-fou d'egress, la résolution sûre est que **le flag le plus restrictif gagne**. Une egress inattendue fait le plus de mal précisément dans l'environnement air-gapped. Le fix skip le POST proprement, avant toute résolution d'URL ou import réseau, avec `EXIT_OK` (honorer `--offline` est correct, pas un échec) + notice claire sur stderr. Nouvelle clé locale `cli.test_webhook.offline_skipped` (EN+FR).

### Tests

[tests/test_v0111_i18n_format_and_offline_webhook.py](../tests/test_v0111_i18n_format_and_offline_webhook.py) — 9 tests (degrade `t()` ×4, `try_t()` ×3 dont KeyError préservé, offline guard ×2 dont guard no-network) + 2 dans `TestTemplateWellFormed` (en+fr). 11 tests pour M-1+M-2. 0 régression.

### Fixes de polish issus de l'audit fonctionnel / qualité-perçue (UX) — F3, F5, F7

Juste après M-1+M-2, un audit fonctionnel / qualité-perçue a été mené sur tout l'outil **en conditions réelles** (audit root live sur Linux Mint 22.3, tous les formats de sortie, la couche éducation `--explain`, les chemins d'erreur, EN+FR). Il a surfacé 7 findings. Quatre sont des changements de contrat/design/comportement déférés à un bundle v0.12.0 planifié : **F1** (le modèle de score domain-average arrondit une déduction `-1` réelle vers un `10/10` de tête, qui coexiste avec "Action required" et sonne contradictoire — la pièce maîtresse, demande du design), **F2** (un finding s'affiche `⚠ [WARNING]` dans le corps mais sous `✖ Action required` dans le résumé), **F4** (`--explain <mauvaise clé>` sort `0`, indistinct d'un succès, sans suggestion "did you mean"), **F6** (le root-gate fire avant la validation non-root). Les trois restants sont triviaux, sans changement de contrat, intégrés à v0.11.1 :

**F3 — le parsing des noms de device fwupd fuyait du junk connecteur.** [bob/checks/firmware.py](../bob/checks/firmware.py). Toutes les commandes système tournent sous `LC_ALL=C` (forcé dans [bob/checks/_run.py](../bob/checks/_run.py) pour une sortie anglaise stable). Mais `fwupdmgr get-updates` dessine son arbre de devices avec des connecteurs Unicode (├ └ ─ │), qui sous `LC_ALL=C` dégradent en `?`. La détection d'arbre échouait, le parser tombait en mode flat et récupérait l'en-tête conteneur + un `?` nu + `??UEFI dbx:` comme 3 "noms de device". Observé live : `3 pending firmware update(s): ASUSTeK ... , ?, ??UEFI dbx:` — nom **et** count faux (3 vs 1 réel). Fix : nouveau `_C_UTF8_LOCALE_ENV` (`LC_ALL=C.UTF-8` — texte anglais, charset UTF-8) passé à fwupd via un nouveau paramètre `env=` sur `_run`. Le parser tree est correct sur entrée correcte — vérifié live : `1 pending firmware update(s): UEFI dbx`. Une garde défense-en-profondeur (`_VALID_DEVICE_NAME_RE`) rejette tout junk résiduel.

**F5 — le hint explain clé-introuvable disait sudo à tort.** `explain.ui.unknown_hint` disait *"Run 'sudo bob --explain list'"*, or `--explain list` ne demande pas sudo (le sibling `invalid_key_hint` était déjà correct). Sudo retiré (EN+FR).

**F7 — les règles orphelines UFW proto-non-spécifiées affichaient un port nu.** [bob/checks/firewall.py::_check_orphan_rules](../bob/checks/firewall.py). Une règle sans protocole (UFW → tcp+udp) s'affichait `57621` à côté de `41681/tcp`. Maintenant `57621/tcp+udp` ; la remediation `ufw delete allow 57621` garde le port nu (seule forme acceptée).

[tests/test_v0111_ux_audit_fixes.py](../tests/test_v0111_ux_audit_fixes.py) — 9 tests (F3 ×4, F5 ×2, F7 ×3).

### Passe de justesse documentaire (DOC-A … DOC-G)

Un audit complet de la doc (cross-check de chaque doc prose + man + help CLI contre le code réel) a tourné dans la même fenêtre ; ses corrections sans risque ont été intégrées. Le *squelette* de la doc était excellent (parité EN/FR, conventions footer/email/URL clean) ; le drift se concentrait sur **deux features au statut changé** + des **compteurs jamais resynchronisés** :

- **`--json-v1`** (retiré en v0.9.0) était encore documenté comme flag utilisable : ligne `sudo bob --json-v1` exécutable dans [TUTORIAL.md](../DOCUMENTS/TUTORIAL.md) + FR, table + exemple dans [README_TECH.md](../DOCUMENTS/README_TECH.md), mention dans [SECURITY.md](../SECURITY.md). Tout corrigé en "retiré en v0.9.0 ; v2 seul schéma".
- **Le profil `workstation`** se contredisait : [README.md](../README.md) le disait "alias rétrocompatible vers `desktop`" et [man/bob-profile.5](../man/bob-profile.5) "shipped mais non consommé par le loader" (comportement pré-v0.8.1) alors que README_TECH/SECURITY le disaient first-class. Réalité ([bob/profiles.py](../bob/profiles.py)) : alias retiré en v0.8.1, `workstation` est un profil first-class business-tier. Sources réconciliées + `workstation` **ajouté à la ligne profil du `--help` + message d'erreur `--profile`** ([bob/cli.py](../bob/cli.py)) où il était omis.
- **Compteurs périmés** : EXPLAIN_KEYS cité 116 / 168 → réel **169 clés / 45 préfixes** ; "43 vérifications" → **34 sections** (matche `--check=list`). Services (38) déjà correct.
- **`UFW_AUDIT_SHARE`** (supprimé v0.5.4) documenté comme env var fonctionnelle dans [man/bob.1](../man/bob.1) (entrée retirée) et [README_DEV.md](../DOCUMENTS/README_DEV.md) (corrigé vers le vrai mécanisme `BOB_SHARE`).
- Dates man bumpées à 2026-06-11.

[tests/test_v0111_doc_accuracy.py](../tests/test_v0111_doc_accuracy.py) — 6 gardes anti-drift (profils `.conf` ⊆ ligne `--help` + message d'erreur ; aucun doc user ne montre un `bob --json-v1` exécutable). Même pattern "post-bug → garde générique" que le literal-drift guard v0.11.0.

### Fuite i18n inverse — français hardcodé dans les commandes SMART disque

Révélé en comparant un audit **anglais** live au français (runs user, 2026-06-10) : les cinq suggestions de commandes `smartctl` dans [bob/checks/disk.py](../bob/checks/disk.py) portaient des **commentaires français hardcodés** (`# lancer un test automatique court`, `# surveiller la progression`, …) — corrects en audit FR mais **fuitant le français dans tout audit anglais**. C'est l'inverse (et plus net) que le F8 déféré : F8 = "non traduit" (défendable pour les titres CIS), ça = mauvaise langue — donc ship maintenant. Fix : cinq clés locale `disk.smart_cmd.{test_short,test_long,watch,abort,history}` (EN+FR) via `_t()`. Scan confirmé isolé à ces 5 strings. Piné par `TestDiskSmartCmdLocalised`.

### Numbers

- **Tests 6336 → 6369** (+33 : 11 pour M-1+M-2 + 16 dans ux_audit_fixes (9 F3/F5/F7 + 7 disk i18n) + 6 gardes doc-accuracy). 0 régression.
- 5 fichiers production (`i18n.py`, `__main__.py`, `_run.py`, `firmware.py`, `firewall.py`, `disk.py`, `cli.py`).
- locale : `offline_skipped`, `unknown_hint`, `disk.smart_cmd.*` (5 clés) — EN+FR.
- 3 test files (nouveaux) + 1 classe locale-linter + release surface complète.

### Upgrade

```
pipx upgrade bodyguard-of-bits
```

Pas d'action de migration requise. `bob --test-webhook --offline` skip maintenant proprement au lieu de POSTer.

**v0.7.x reste EOL** (déclaré dans [SECURITY_FR.md](../SECURITY_FR.md) depuis v0.8.1). **v0.6.x reste EOL** (déclaré en v0.7.2).

### Leçons

- **Un audit clean est un résultat valide — mais les deux minors trouvés étaient de vrais trous de contrat**, pas cosmétiques : le contrat never-crash d'i18n avait un trou pour les templates malformés ; le contrat no-egress de `--offline` avait un trou pour `--test-webhook`.
- **Fixer à la couche la plus forte.** M-1 ship un degrade runtime ET un linter CI qui empêche la mauvaise data d'atterrir.
- **Le filter conservateur n'est pas "ne rien shipper sur un audit clean".** 0 C / 0 I = pas d'urgence, mais deux fixes cheap qui restaurent des contrats passent "gain × risque".

---

## [v0.11.0] — 10-06-2026

**Première release v0.11.x — BREAKING bundle : hygiene + design fix.**

Ouvre la branche v0.11.x. Un BREAKING bundle planifié et conservateur (pas un patch de réaction à un audit) : le scope a été figé à l'avance ([[project_v0110_plan]]) et approuvé avant l'implémentation. Deux items BREAKING, trois items engineering/test, un refresh documentaire, et une passe d'audit pre-ship.

### Pourquoi ce bundle, et pourquoi F-1 N'Y est PAS

Le filter backlog v0.11.0 a appliqué "gain × risque = STOP" ([[feedback_conservative_refactor]]) à chaque item déféré :

| Item | Verdict | Raison |
|---|---|---|
| **F-1 parallel checks** | **DEFER indéfiniment** | Gain perf 30s → 5-10s MAIS zéro signal user perf sur 3+ majeures. Risque thread-safety élevé. Tranché — pas re-proposé chaque cycle. |
| **M-3 ssh client Host scope** | **GO** | Vrai contract leak que v0.10.1 a self-introduit (son explain text recommande "restrict per-Host" mais le checker peut pas distinguer). |
| **D-4 Rank 2-8 KILL** | **GO** | Règle kill-dormant (précédent v0.8.4) : 5+ majeures, zéro signal, entries shim inertes. |
| **CI literal-drift guard** | **GO** | Cheap ; prévient la récurrence de la classe de bug v0.10.2 I-1. |
| **Posture matrix tests** | **GO** | Cheap ; ferme le test debt masking-branch que le bug v0.10.2 a exposé. |
| **SNAPSHOT refresh** | **GO** | Drift doc accumulé v0.6.0 → v0.10.x. |
| **Audit pre-ship** | **GO** | Pattern habituel pre-major. A trouvé + fixé un vrai problème. |

### M-3 — sémantique de scope Host `~/.ssh/config` (BREAKING)

Pre-v0.11.0 [bob/checks/ssh/_subchecks.py::_check_client_config](../bob/checks/ssh/_subchecks.py) aplatissait chaque entry parsée — une directive dans un block `Host pattern` restreint était évaluée exactement comme si elle était dans le block global `Host *`. Ça contredisait directement la propre advice de remediation de BOB : l'explain text v0.10.1 pour le transfert X11 client-side recommande "restrict it per-Host block", mais un operator qui faisait exactement ça était quand même WARNé avec une déduction de `-1` point. Suivre l'advice de BOB ne silençait pas BOB.

v0.11.0 rend les deux directives de **forwarding** scope-aware. Politique de sévérité par directive :

| Directive | Scope global (`Host *`) | Scopé à un Host spécifique |
|---|---|---|
| `ForwardX11 yes` | WARN + `-1` | **INFO, sans déduction** |
| `ForwardAgent yes` | WARN + `-1` | **INFO, sans déduction** |
| `StrictHostKeyChecking no` | ALERT + `-3` | **ALERT + `-3` (inchangé)** |
| `UserKnownHostsFile /dev/null` | ALERT + `-3` | **ALERT + `-3` (inchangé)** |

Les directives de vérification de clé d'hôte restent ALERT dans **n'importe quel** scope : désactiver la vérification de clé d'hôte est une exposition MITM même scopé à un host.

**Le cas multi-pattern (audit pre-ship I-1).** Le parser client-config stocke le reste entier de la ligne `Host` verbatim, donc `Host bastion *` donne `entry.host == "bastion *"`. Un test naïf `entry.host != "*"` traiterait ça comme scopé — mais OpenSSH applique le block si **n'importe quel** pattern matche, et un `*` nu matche tout host, donc `Host bastion *` est globalement effectif. L'audit sub-agent pre-ship a chopé ça comme un trou d'évasion de scoring. Le test shippé tokenise : `scoped = "*" not in entry.host.split()`. Un wildcard de sous-domaine borné (`Host *.example.com`) n'a pas de token `*` nu et reste scopé.

**BREAKING** : une directive de forwarding scopée déduisait avant 1 point (WARN) ; maintenant c'est INFO sans déduction, donc le score **monte**.

Nouvelles clés locale (EN + FR, avec placeholder `{host}`) : `ssh.client_forward_agent_scoped`, `ssh.x11.forwarding.client_scoped`. Ce sont des clés INFO, donc — comme les clés INFO existantes `ssh.client_config_ok` — intentionnellement **pas** dans `EXPLAIN_KEYS`.

### D-4 Rank 2-8 KILL

v0.10.0 a shippé `SUBCHECK_RENAMES_V100` comme **foundation** pour un split D-4 8-ranks planifié, mappant 14 clés legacy. Seul **Rank 1** (`ssh.x11_forwarding`, shippé v0.10.1) a jamais été implémenté.

Les Ranks 2-8 n'ont jamais été implémentés. Les emit sites produisent encore les clés monolithiques (`ssh.host_key_dsa`, `ssh.weak_ciphers`, …), donc leurs entries shim étaient **inertes** : leurs patterns canoniques étaient émis par **rien** (vérifié par l'audit pre-ship), `matches_legacy_ignore` ne firait jamais, et un `ignore.yml` avec une clé monolithique toujours-live est géré par le path exact-match dans `ScoreEngine.apply`.

Avec zéro signal user sur 5+ majeures, v0.11.0 retire les 13 entries inertes (règle kill-dormant, même call que le retrait v0.8.4 `compare-breakdown-diff`). La map est maintenant `{ssh.x11_forwarding: ssh.x11.forwarding.*}`. **Behaviour-preserving**. Piné par [tests/test_v0110_d4_rank28_kill.py](../tests/test_v0110_d4_rank28_kill.py) — Rank 1 survit + marche ; les 14 clés killées sont absentes ; et un échantillon représentatif est asserté comme toujours une **clé live émise** dans son module de check.

### CI guard — détection de literal key-drift

[tests/test_v0110_legacy_key_drift_guard.py](../tests/test_v0110_legacy_key_drift_guard.py) généralise le guard statique v0.10.2 à **tous** les renames historiques. Sweep AST sur tout le source production `bob/` pour les string literals qui référencent une clé *renommée-away* : les 7 prefixes v0.9.0 D-1 (data-driven depuis `SECTION_RENAMES_V090`) + la clé Rank 1 v0.10.1 `ssh.x11_forwarding`. Les clés D-4 Rank 2-8 sont **délibérément hors scope** (live, pas renommées). Modules allowlisted : `_v090_renames.py`, `_v100_subcheck_renames.py`, `compare.py`, `explain.py`. Docstrings skippés via AST.

C'est la classe exacte de bug qui a laissé l'escalation posture I-1 v0.10.2 dead 3 majeures. Le guard fait fail CI le prochain drift de rename cross-module au lieu de shipper silencieusement.

### Posture matrix tests

[tests/test_v0110_posture_matrix.py](../tests/test_v0110_posture_matrix.py) énumère la matrice complète 2×2×2 = 8 cellules de `set_posture_from_engine` + résolution de priorité + isolation de branche (la leçon v0.10.2 : une branche de masking peut cacher une branche morte pendant des majeures).

### SNAPSHOT.md refresh

`DOCUMENTS/SNAPSHOT.md` rafraîchi de v0.10.0 à v0.10.2 (+ v0.11.0 in preparation). Footer préservé.

### Audit pre-ship

Audit sub-agent ciblé sur le diff v0.11.0 → 3 findings : **I-1 (important)** trou d'évasion scope multi-pattern, **fixé avant tag** ; **M-1 (minor)** blocks `Match` non parsés (fail-safe, déféré) ; **M-2 (minor)** scope-awareness intentionnellement partiel, no-op.

### Numbers

- **Tests 6268 → 6336** (+68 : 15 posture matrix + 4 drift guard + 37 D-4 kill pin + 12 ssh Host scope). 0 régression.
- 2 fichiers production + 2 fichiers locale + 4 nouveaux test files + SNAPSHOT refresh.

### Upgrade

```
pipx upgrade bodyguard-of-bits
```

Les operators qui ont scopé une directive `ForwardX11` / `ForwardAgent` per-Host voient le finding passer de WARN à INFO (le score s'améliore). Pas de migration `ignore.yml` requise.

**v0.7.x reste EOL** (déclaration formelle dans [SECURITY_FR.md](../SECURITY_FR.md) depuis v0.8.1). **v0.6.x reste EOL** (déclaré en v0.7.2).

### Leçons

- **Les BREAKING bundles planifiés marchent quand le scope est figé à l'avance.**
- **Un item de test-debt d'un bug passé paye off le même cycle** (posture matrix + CI drift guard transforment le bug v0.10.2 en protection régression permanente).
- **L'audit pre-ship gagne sa place** : a chopé un vrai trou d'évasion de scoring dans la feature même dont le point est la sémantique de scope.

---

## [v0.10.2] — 10-06-2026

**Deuxième patch hardening v0.10.x — fix I-1 issu de l'audit deep hardening post-v0.10.1.**

### Le cycle : audit same-day → ship same-day

Après que v0.10.1 ait été taggé plus tôt aujourd'hui, un sub-agent a roulé la passe d'audit deep hardening standard sur le codebase post-v0.10.1. L'audit a retourné 4 findings :

| ID | Sévérité | Surface | Verdict |
|---|---|---|---|
| **I-1** | Important | `bob/scoring.py:739` (posture escalation, legacy key) | **GO v0.10.2** |
| M-1 | Minor | `bob/checks/ssh/_subchecks.py:507-516` (Host blocks dupliqués) | DEFER |
| M-2 | Minor | `bob/checks/ssh/_subchecks.py:462-466` (hoist `client_config_q`) | KILL (cosmetic) |
| M-3 | Minor | `bob/checks/ssh/_parsers.py:334-351` (semantics scope `Host`) | DEFER → candidat v0.11.x |

Filter workflow conservateur ([[feedback_conservative_refactor]] "gain × risque = STOP") : seul I-1 passe le test coût/valeur parce que c'est un vrai bug d'escalation avec régression security-relevant, masqué par une autre branche posture mais visiblement broken sur une shape de déploiement qui existe in the wild. Les 3 minors fail parce que pré-existants (zéro signal user sur 5+ majeures) ou purement cosmétiques.

### Le bug

`bob/scoring.py::set_posture_from_engine` cherchait des findings avec la clé legacy v0.7.x / v0.8.x pour flip le posture flag `iptables_input_accept` :

```python
engine.set_posture(
    firewall_inactive=not fw_active,
    iptables_input_accept=any(
        f.key == "iptables_nft.input_accept" for f in engine.findings  # ← clé v0.7.x / v0.8.x
    ),
    firewall_domain_score=_fw_score,
)
```

Le prefix `iptables_nft.*` a été renommé `firewall_iptables.*` en **v0.9.0 D-1** dans le cadre du bundle BREAKING qui a fermé le deferred architectural cleanup v0.7.0. Le rename est documenté dans `bob/_v090_renames.py::SECTION_RENAMES_V090` et la clé canonique est émise live par `bob/checks/iptables_nftables.py:174` depuis v0.9.0.

La comparaison string-literal en `scoring.py:739` a arrêté de matcher quoi que ce soit à la release v0.9.0. **L'escalation iptables-passthrough de posture est dead silencieusement depuis 3 majeures** (v0.9.0 → v0.9.1 → v0.9.2 → v0.10.0 → v0.10.1).

### Pourquoi aucun user n'a signalé

`set_posture` a 3 triggers d'escalation, en ordre de priorité :

1. `firewall_inactive=True` → HIGH (`scoring.posture.firewall_inactive`)
2. `iptables_input_accept=True` → HIGH (`scoring.posture.iptables_input_accept`)
3. `firewall_domain_score <= 3` → MEDIUM (`scoring.posture.firewall_domain_low`)

La shape de déploiement la plus commune qui surface le risk iptables-passthrough est **UFW disabled + iptables INPUT ACCEPT**. Cette shape trigger la branche (1) qui escalate déjà à HIGH. Donc le risk floor user-visible est correct *pour le cas le plus commun*.

La shape qui régresse silencieusement est la combinaison plus rare **UFW active + iptables INPUT ACCEPT** — ex. un operator a activé UFW mais a laissé une règle iptables passthrough legacy d'une config précédente. Dans ce cas, branche (1) est False, branche (2) était supposée fire sur le finding iptables mais la comparaison literal n'a jamais matché, donc ni (1) ni (2) n'a escaladé. Le risk floor a régressé de HIGH (pre-v0.9.0) à LOW (post-v0.9.0).

### Le fix

[bob/scoring.py:739](../bob/scoring.py#L739) — update le literal pour matcher la clé canonique v0.9.0+ avec commentaire inline qui capture le **why** et le **failure mode** pour les audits futurs.

### Pourquoi ce fix unique couvre les 2 call sites

`set_posture_from_engine` est la single source of truth pour la computation posture depuis v0.7.3 M-10. Appelé depuis `bob/__main__.py::audit` et `bob/watch.py:109`. Le dedup signifie que le fix v0.10.2 à `scoring.py` se propage aux 2 surfaces sans changement additionnel.

### Tests

[tests/test_v0102_posture_iptables_key.py](../tests/test_v0102_posture_iptables_key.py), NOUVEAU, 7 tests sur 2 classes + 1 parametrize.

**`TestPostureIptablesKey`** (4 tests) : canonical_key_triggers + legacy_key_does_not + no_finding + fw_inactive_still_escalates.

**`TestNoLegacyKeyInLiveCheck`** (2 tests static guards) : scoring.py sweep + full bob/ sweep avec allowlist `_v090_renames.py` + `compare.py`.

**Parametrize** (1 test) : canonical_key_present_in_explain_catalog (pin EXPLAIN_KEYS contract).

Total : **+7 tests** (6261 → 6268). 0 régression.

### Pourquoi les 3 minors sont déférés

- **M-1** — Host blocks dupliqués triple-deduct. Pré-existant 4 directives client. Zéro signal user 5+ majeures.
- **M-2** — Cosmetic hoist. Aucun impact mesurable. KILL.
- **M-3** — `_check_client_config` flatten `Host` blocks. Vrai contract leak introduit par v0.10.1 (l'explain text recommande "restrict per-Host" mais le checker peut pas distinguer). Déféré v0.11.x comme refinement style D-4 ; revisite si signal user sur faux-positif per-Host scoping.

### Numbers

- **Tests 6261 → 6268** (+7). 0 régression.
- 1 fichier production code modifié (1 ligne + commentaire de contexte).
- 1 nouveau test file (7 tests).

### Upgrade

```
pipx upgrade bodyguard-of-bits
```

Pas d'action de migration requise depuis v0.10.1.

**v0.7.x reste EOL** (déclaration formelle dans [SECURITY_FR.md](../SECURITY_FR.md) depuis v0.8.1).
**v0.6.x reste EOL** (déclaré en v0.7.2).

### Audit pattern : same-day audit → same-day ship est le pattern

v0.7.1, v0.8.1, v0.9.1, v0.9.2, v0.10.2. Le rythme "ship un major, audit, ship le hotfix same-day ou next-day" a tenu sur les 4 cycles BREAKING / hardening les plus récents. Le filter workflow conservateur sélectionne seulement les bugs qui requirent vraiment de shipper.

### Leçons

- **Les comparaisons literal dans les couches posture / scoring doivent être pinées par tests régression contre le contract canonical.**
- **Les renames cross-module nécessitent un literal-string sweep.**
- **Les branches de masking font les régressions silencieuses invisibles.**

---

## [v0.10.1] — 10-06-2026

**Premier patch hardening v0.10.x — D-4 Rank 1 split `ssh.x11_forwarding` + NOUVELLE détection client-side ForwardX11.**

### Pourquoi ce split unique, pourquoi maintenant

Le workflow conservateur v0.10.x (proposé dans le ship v0.10.0 + memory note) applique "gain × risque = STOP" de [[feedback_conservative_refactor]] aux 8 candidates ranked D-4 de l'audit sub-agent. Le filtre :

| Item | Gain mesurable | Signal user | Risque | Verdict |
|---|---|---|---|---|
| D-4 Rank 1 (ssh.x11 server + NEW client) | ✓ nouvelle capacité de détection (zéro pre-v0.10.1) | indirect | L | **GO** |
| D-4 Rank 2 (DSA family rename) | ✗ cosmétique | zéro | L | DEFER |
| D-4 Rank 3-8 | △ granular ignore.yml | zéro | M | DEFER |
| F-1 parallel checks | ✓ 30s → 5-10s perf | **zéro signal perf** | H | DEFER jusqu'au signal |

Rank 1 ship parce qu'il apporte une **détection précédemment manquante** (client-side X11 forwarding via `~/.ssh/config ForwardX11 yes`), pas qu'un rename cosmétique de clé. Les 7 autres ranks fail le filtre "gain mesurable" sans signal user — ils restent déférés indéfiniment per la règle kill-dormant-features établie par v0.8.4 ([[project_v084_shipped]] a retiré `compare-breakdown-diff` après zéro signal sur 5 majeures).

### Rename server-side

[bob/checks/ssh/_directives.py](../bob/checks/ssh/_directives.py) — la row `_BadDirective` existante pour `x11forwarding` reprend la clé canonique renommée `ssh.x11.forwarding.server`. Logique parsing sshd_config inchangée.

### Détection client-side (NOUVELLE capacité)

[bob/checks/ssh/_subchecks.py::_check_client_config](../bob/checks/ssh/_subchecks.py) — nouvelle branche `elif k == "forwardx11" and v == "yes":` à côté du `forwardagent` existant, émet `ssh.x11.forwarding.client` avec `points=1` warn + detail + cmd remediation.

### Pourquoi le transfert X11 client-side importe

Le protocole X11 **n'a aucune frontière de sécurité entre applications locales et forwardées**. Quand un user fait `ssh -X host` ou a `ForwardX11 yes` dans `~/.ssh/config`, le serveur X local est exposé à l'hôte distant via le tunnel SSH :

- Le distant peut appeler `xwd` pour prendre des captures d'écran du bureau local
- Le distant peut appeler `xdotool` pour injecter des frappes clavier dans n'importe quelle application X locale (terminal, password manager, browser)
- Le distant peut lire le presse-papiers local via `xclip` / `xsel`
- Le distant peut lire les titres de fenêtre, le contenu de la fenêtre focusée, et les selection buffers de la session X

C'est un trust model wide-open : le distant a effectivement l'équivalent d'un accès process local à la session X. Pre-v0.10.1 BOB avait **zéro détection** de cette configuration. L'asymétrie est fixée en v0.10.1.

Le guidance remediation pointe vers `ForwardX11Trusted no` (extension SECURITY X11) comme path de hardening per-Host quand le transfert X11 est vraiment nécessaire, plus `ssh -X` on-demand comme alternative à `ForwardX11 yes`-by-default.

### Back-compat — ignore.yml + --explain

- Pre-v0.10.1 entries `ignore.yml` avec `ssh.x11_forwarding` couvrent les 2 nouvelles sub-keys via le shim v0.10.0 [SUBCHECK_RENAMES_V100](../bob/_v100_subcheck_renames.py) (le glob fnmatch `ssh.x11.forwarding.*`).
- Pre-v0.10.1 `bob --explain ssh.x11_forwarding` résout vers le contenu server-side via la nouvelle entry EXPLAIN_KEY_ALIASES. **Premier alias live après le retrait D-3 v0.9.0** — la rationale "garder le dict pour qu'un futur rename ait un migration path one-line" rencontre son premier user.

### Locale (EN + FR)

Migration namespace `ssh.x11_forwarding` → `ssh.x11.forwarding.server` + 4 nouvelles entries client-side (message + detail + explain.{title,why,how}) avec wording risque client-side dédié.

### EXPLAIN_KEYS catalog

168 → **169** (+1 pour le nouveau `ssh.x11.forwarding.client`). Le constant `test_total_keys_match_audit_count` bumpé. La regex canonical_pattern étendue avec exception `_SSH_X11_FORWARDING_RE` (soeur des exceptions `_FILE_PERMS_MULTI_RE` et `_SERVICES_MULTI_RE` existantes).

### CIS refs

| Key | Référence CIS |
|---|---|
| `ssh.x11.forwarding.server` | CIS Ubuntu 22.04 L1 — 5.2.6 (unchanged) |
| `ssh.x11.forwarding.client` | Best practice (no formal CIS code today) |

### Tests

[tests/test_v0101_ssh_x11_client.py](../tests/test_v0101_ssh_x11_client.py) — 10 tests dédiés sur 3 classes (`TestServerSideRename`, `TestClientSideDetection`, `TestBackCompat`) + 9 updates ailleurs. Total **+19 tests** (6242 → 6261). 0 régression.

### Numbers

- **Tests 6242 → 6261** (+19). 0 régression.
- 2 fichiers code production modifiés (`_directives.py`, `_subchecks.py`).
- 1 fichier module modifié (`explain.py` — EXPLAIN_KEY_ALIASES entry + EXPLAIN_KEYS rename).
- 2 fichiers locale modifiés (EN + FR — migration namespace + 4 nouvelles entries).
- 1 fichier CIS refs + 2 fichiers profile + 1 fichier bash completion modifiés.
- 1 nouveau test file + 4 test files existants modifiés.

### Upgrade

```
pipx upgrade bodyguard-of-bits
```

Pas d'action de migration requise depuis v0.10.0 ou v0.9.x.

**v0.7.x reste EOL** (déclaration formelle dans [SECURITY_FR.md](../SECURITY_FR.md) depuis v0.8.1).
**v0.6.x reste EOL** (déclaré en v0.7.2).

### Field test scope

Le workflow conservateur ne requiert pas une campagne cross-distro 5-distros pour un patch D-4 single-rank. Un smoke local sur l'host (operator avec `~/.ssh/config` pour exercer la détection client-side) couvre le nouveau code path ; la parité locale EN+FR est enforced par les tests automatisés `TestClientSideDetection::test_locale_keys_present_in_both_locales` + `test_explain_content_present_in_both_locales`.

### Déféré aux futurs patches v0.10.x (toujours aligné avec workflow conservateur)

- **D-4 Rank 2-8** — cosmétique / granular ignore.yml. Pas de signal user → pas de ship.
- **F-1 parallel checks** — perf 30s → 5-10s. **Zéro signal user perf**. Ne pas shipper sans demande mesurée.
- **SNAPSHOT.md deep refresh** — module-by-module + tailles fichier. Low-priority doc patch candidate.

### Leçons

- **EXPLAIN_KEY_ALIASES kept-but-empty paye off.** Le retrait D-3 v0.9.0 a vidé le dict mais explicitement gardé la machinery `normalize_key()` pour qu'un futur rename ait un migration path one-line. v0.10.1 D-4 Rank 1 est exactement ce futur rename. Pattern validé.
- **Workflow conservateur a tenu en pratique.** Le proposal v0.10.x a appliqué "gain × risque = STOP" aux 9 items déférés ; 1 a passé le filtre, 8 ont fail.
- **Ajouter une nouvelle détection est qualitativement différent du rename d'une détection existante.** Le framing coût/valeur surface cette distinction.

---

## [v0.10.0] — 09-06-2026

**Première release v0.10.x — release de préparation** ouvrant la prochaine fenêtre de bundle BREAKING. Ship la foundation du shim de migration sub-check D-4 + ScoreEngine ignore.yml back-compat wiring + refresh SNAPSHOT.md, en déférant intentionnellement les implémentations D-4 splits réelles et le refactor F-1 parallel-check aux patches hardening v0.10.1+.

### Pourquoi une release de préparation

Deux audits sub-agent ont été runs le 2026-06-08 pour scoper le travail bundle BREAKING v0.10.0 :

1. **Audit candidates D-4 sub-checks** — walk `bob/checks/*.py` à la recherche de finding keys qui lump plusieurs subcases sous un seul nom. Identifié 8 candidates split ranked avec estimations d'effort par split, plus une liste "do NOT split" de 5 keys qui ressemblent à des candidates mais restent unifiées. Estimation effort D-4 total : **≈ 20 heures** (le shim wildcard est la nouveauté principale vs le shim baseline simple `str → str` v0.9.2).

2. **Audit thread-safety F-1 parallel-check** — inventaire shared state dans `bob/runner.py::run_checks` (engine, report, output, i18n, GEO cache, network_context, audited_ports cross-check), classifié les check functions comme pure vs side-effecting (~38 sur ~38 sont pure une fois leur snapshot collecté), identifié torn-read risks dans les apt-related checks (apt-get -s + apt-cache policy prennent un frontend lock). Recommandé **Option B** : Phase 0 séquentielle firewall/ports/network_context (cross-check deps) + Phase 1 `ThreadPoolExecutor(max_workers=min(8, cpu_count()))` snapshot+check fan-out avec apt slot serialization + Phase 2 merge séquentielle en ordre canonique `_SECTIONS`. Estimation effort F-1 total : **≈ 6-8 heures** + 4 nouveaux test files determinism.

Effort combiné estimé : **≈ 30 heures** pour le bundle BREAKING v0.10.0 complet (D-4 splits + F-1 + refresh SNAPSHOT + release surface), ce qui dépassait une session ship unique. Le call pragmatique a été de **stager le travail** :

  - **v0.10.0 (cette release)** — ship la foundation du shim D-4 pour que les huit patches follow-up puissent landing sans re-toucher le fichier shim. Ship le refresh SNAPSHOT.md pour que le doc project-snapshot couvre les trois majeures de drift sur lesquelles la branche v0.10.x sit. Bump la version pour marquer la branche v0.10.x ouverte.
  - **v0.10.1+** — implémenter les 8 D-4 splits un par un (Rank 1 en premier comme exemple canonique ssh.x11 server/client), chacun avec son propre locale + EXPLAIN + tests. Implémenter F-1 Option B dans un patch dédié avec les quatre test files determinism landing à côté du refactor.

Cette approche miroite le cycle v0.7.x → v0.8.x où le bundle BREAKING a landed comme single ship (v0.8.0 + drift batch v0.8.0 + items déférés v0.7.0) et les patches hardening ont follow-up (v0.8.1 / v0.8.2 / v0.8.3 / v0.8.4).

### Foundation shim migration D-4

[bob/_v100_subcheck_renames.py](../bob/_v100_subcheck_renames.py) — nouveau module 90-lignes exportant `SUBCHECK_RENAMES_V100` (dict 14 entries legacy v0.9.x → patterns glob `fnmatch`) + `matches_legacy_ignore()` + `any_legacy_ignore_matches()` helpers.

La shape a changé vs `bob/_v090_renames.py` v0.9.2 parce que D-4 couvre trois topologies de migration en une map :

1. **1-to-1 simple renames** (Rank 2 DSA family) — le pattern est la target exacte sans wildcard
2. **1-to-N enumerated splits** (Rank 1 ssh.x11 server+client, Rank 5 journald, Rank 6 firewall_rules duplicate) — le pattern utilise `*` pour couvrir chaque sibling canonique
3. **1-to-many runtime-discovered** (Rank 4 samba per-share, Rank 7 kernel modules per-name, Rank 8 SSH weak crypto per-algo) — le set de keys canoniques est unbounded, le wildcard est la seule représentation viable

Le runtime helper `matches_legacy_ignore(finding_key, ignore_entry)` résout `ignore_entry` contre `SUBCHECK_RENAMES_V100` et run `fnmatch.fnmatch(finding_key, pattern)`.

### Wiring ScoreEngine.apply ignore.yml back-compat

[bob/scoring.py::ScoreEngine.apply](../bob/scoring.py) a été update pour consulter à la fois le path exact-match existant ET le nouveau path legacy-glob via `_is_ignored()` helper interne.

Aujourd'hui ça ne change pas de behavior visible parce qu'aucun check émet les nouvelles sub-keys canoniques. Le shim devient load-bearing dès que v0.10.1 ship le premier split D-4.

### Refresh SNAPSHOT.md

[DOCUMENTS/SNAPSHOT.md](../DOCUMENTS/SNAPSHOT.md) a été refresh pour la dernière fois pour v0.7.4 (2026-06-02, refresh depuis baseline v0.6.0). v0.10.0 ajoute deux paragraphes : drift v0.7.4 → v0.9.2 (couvre les cycles v0.8.x et v0.9.x) + paragraphe préparation v0.10.0 (stratégie staging + estimations d'audit).

### Numbers

- **Tests 6242 → 6242** (pas de delta dans cette release de préparation). 0 régression.
- 1 nouveau module ([bob/_v100_subcheck_renames.py](../bob/_v100_subcheck_renames.py)) — 90 lignes.
- 1 fichier code production modifié ([bob/scoring.py](../bob/scoring.py)) — `_is_ignored` helper + consultation `any_legacy_ignore_matches`, ~15 lignes changées.
- 1 fichier documentation modifié ([DOCUMENTS/SNAPSHOT.md](../DOCUMENTS/SNAPSHOT.md)) — 3 paragraphes ajoutés.
- 4 surfaces changelog + TESTING.md + man pages + debian + rpm + memory note bumpées per convention.

### Upgrade

```
pipx upgrade bodyguard-of-bits
```

Pas d'action de migration requise depuis v0.9.x. La foundation shim D-4 ne change pas le behavior visible sur les entries `ignore.yml` existantes parce que les keys legacy ne sont pas encore émises comme sub-keys canoniques.

**v0.7.x reste EOL** (déclaration formelle dans [SECURITY_FR.md](../SECURITY_FR.md) depuis v0.8.1).
**v0.6.x reste EOL** (déclaré en v0.7.2).

### Déféré à v0.10.1+ (intentionnellement stagé)

8 splits D-4 (Rank 1-8) avec leur effort estimé chacun + F-1 Option B refactor + 4 test files determinism — tous décrits avec file:line dans les reports audit sub-agent enregistrés dans le transcript de session projet.

### Leçons

- **Stage les bundles BREAKING quand l'effort estimé par l'audit dépasse une session ship unique.** Les audits v0.10.0 ont estimé ~30 heures de travail d'implémentation. Shipper la foundation shim dans une release de préparation veut dire que les huit patches follow-up n'ont pas besoin de re-toucher le fichier shim, et la surface de bug est petite par patch au lieu d'une grosse surface à travers le bundle.
- **Les audits sub-agent restent la façon la moins chère de scoper un bundle BREAKING.** Deux audits parallèles tournant en background pour ~3 min chacun ont produit des file:line citations concrètes + listes ranked candidate + estimations d'effort + Options recommandées qui ont informé la décision de staging.
- **La foundation shim est forward-compatible** — ajouter un nouveau rename D-4 en v0.10.x+ est une entry one-line dans `SUBCHECK_RENAMES_V100`.

---

## [v0.9.2] — 08-06-2026

**Ferme les deux gaps i18n / UX documentés dans le CHANGELOG v0.9.1 comme "déférés à v0.10.0+"** — tous deux surfacés par la campagne field test cross-distro v0.9.0. Les deux sont purement additifs (pas de changement BREAKING wire-format, pas de risque pour le chemin audit golden), donc ils fit naturellement comme un patch v0.9.x plutôt que d'attendre v0.10.0.

### BaselineLoadError i18n

Pre-v0.9.2, les quatre sites raise `BaselineLoadError` dans [bob/compare.py](../bob/compare.py) utilisaient des messages anglais hardcoded même sur systèmes FR. Seul le prefix "Erreur :" était localisé (via la clé locale `cli.error.prefix` dans le path d'affichage erreur [bob/__main__.py](../bob/__main__.py)), le body du message lui-même restait anglais.

Contrairement au problème F-3 v0.9.0 (qui firait avant `i18n.init()`), ces raises se passent APRÈS `i18n.init()` (load_baseline est invoqué depuis le chemin audit, pas depuis `parse_args`), donc les messages PEUVENT être proprement i18n'd via le helper `bob._i18n_safe.t_or_hardcoded`.

Quatre nouvelles clés locale landent sous `compare.baseline_load.*` (EN + FR) :

| Clé                                  | Baseline EN                                                                                                                                                  | Localisation FR                                                                                                                                                |
|--------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `not_found`                           | `Baseline file not found: {path} — check the path and that the file exists on this machine.`                                                                  | `Baseline introuvable : {path} — vérifie le chemin et que le fichier existe sur cette machine.`                                                                  |
| `invalid_json`                        | `Baseline file {path} could not be read or parsed as JSON: {error}`                                                                                           | `Le fichier baseline {path} n'a pas pu être lu ou parsé comme JSON : {error}`                                                                                    |
| `v1_schema`                           | `Baseline file {path} carries the legacy v0.6.x schema (schema_version="1") which was retired in v0.9.0 F-3. Re-generate the baseline on a v0.9.0+ host.`     | `Le fichier baseline {path} porte le schéma legacy v0.6.x (schema_version="1") qui a été retiré en v0.9.0 F-3. Régénère le baseline sur un host v0.9.0+.`        |
| `bad_shape`                           | `Baseline file {path} has unexpected shape: {error}`                                                                                                           | `Le fichier baseline {path} a une forme inattendue : {error}`                                                                                                    |

Le helper `t_or_hardcoded` fallback vers la baseline EN au module-level quand i18n n'est pas initialisée — même pattern que la consolidation `bob/_i18n_safe.py` v0.8.2.

Post-v0.9.2 le système FR montre :

```
Erreur : Baseline introuvable : /tmp/X — vérifie le chemin et que le fichier existe sur cette machine.
```

### Migration shim baseline cross-version

Pre-v0.9.2, un baseline écrit par v0.7.x / v0.8.x portait des finding keys avec des prefixes renommés en v0.9.0 D-1 :

```
iptables_nft.input_accept
iptables_nft.forward_accept
cron_audit.pipe_to_shell
...
```

L'audit v0.9.0+ émet les prefixes canoniques (`firewall_iptables.input_accept`, `cron.pipe_to_shell`, …), donc `compute_delta` voyait le même problème physique comme *résolu* (vieille clé dans `prev.finding_keys`) ET *nouveau* (clé canonique dans `curr.finding_keys`). Le field test Ubuntu 26.04 a surfacé le bug déterministiquement :

```
✔ [OK] Résolu : iptables_nft.input_accept
⚠ [ATTENTION] Nouveau finding : firewall_iptables.input_accept
```

Deux findings affichés pour le même problème sous-jacent. Documenté dans le CHANGELOG v0.9.0 comme "les entries ignore.yml doivent être migrées à la main" — mais c'était le path diff, pas ignore.yml.

Le fix est un tiny pure transform dans [bob/_v090_renames.py](../bob/_v090_renames.py) :

```python
def remap_finding_key(key: str) -> str:
    if "." not in key:
        return key
    prefix, _, suffix = key.partition(".")
    new_prefix = SECTION_RENAMES_V090.get(prefix)
    if new_prefix is None:
        return key
    return f"{new_prefix}.{suffix}"
```

Wire dans `load_baseline` après le parse JSON raw, avant la construction AuditBaseline.

Couvre les 7 renames D-1. Self-contained :

- Ne modifie PAS le fichier baseline on-disk (le `save_baseline` du prochain audit écrit les noms canoniques — self-healing naturel)
- N'affecte PAS les baselines déjà écrits par v0.9.0+ (le shim est idempotent sur input canonique ; `remap_finding_key("ssh.password_auth")` retourne `"ssh.password_auth"` inchangé)
- Ne touche PAS la sémantique `ignore.yml` (requiert toujours une migration manuelle per le contrat v0.9.0)

Post-v0.9.2, le même scénario field test Ubuntu 26.04 surface proprement :

```
ℹ [INFO] Score inchangé
✔ [OK] Aucun changement détecté depuis le dernier audit
```

### Extraction map partagée

Pre-v0.9.2 la map legacy → canonical vivait inline dans [bob/runner.py](../bob/runner.py) comme `_RENAMED_SECTIONS_V090`. L'extraire dans un module dédié [bob/_v090_renames.py](../bob/_v090_renames.py) était nécessaire parce que :

- `bob/compare.py` a besoin de la map pour le migration shim
- `bob/compare.py` ne peut pas importer depuis `bob/runner.py` (runner importe déjà depuis compare → circulaire)
- Dupliquer le dict risquerait un drift entre les deux call sites (un contributeur v0.10.0 ajoute une entry à un mais pas à l'autre)

[bob/runner.py](../bob/runner.py) garde le nom legacy `_RENAMED_SECTIONS_V090` comme re-export back-compat pointant vers le dict partagé :

```python
from bob._v090_renames import SECTION_RENAMES_V090 as _RENAMED_SECTIONS_V090
```

[tests/test_v092_baseline_i18n_and_shim.py::TestV090RenamesSharedModule::test_runner_legacy_alias_points_at_shared_module](../tests/test_v092_baseline_i18n_and_shim.py) asserte l'identité `is` (même objet) — le drift entre les deux noms devient impossible. `test_seven_entries_match_d1_table` pin le contenu exact de la map contre la table CHANGELOG v0.9.0 documentée.

### Numbers

- **Tests 6212 → 6242** (+30 sur 4 classes) :
  - `TestV090RenamesSharedModule` (2 tests) : back-compat shared-map + contrat 7-entries
  - `TestRemapFindingKey` (18 tests) : 8 parametrize legacy → canonical + 6 pass-through canonical + 4 edge cases unaffected (y compris suffix-with-dots)
  - `TestLoadBaselineMigrationShim` (4 tests) : baselines v0.7.x et v0.8.x remappés, pass-through v0.9.x, guard pre-v1.22 absent-field
  - `TestBaselineLoadErrorI18n` (6 tests) : rendering FR pour 3 des 4 messages + sanity présence locale-key dans les deux locales
- 0 régression.
- Code production : ~50 lignes changées à travers [bob/_v090_renames.py](../bob/_v090_renames.py) (nouveau fichier, 50 lignes), [bob/runner.py](../bob/runner.py) (5 lignes — le dict inline remplacé par l'import), [bob/compare.py](../bob/compare.py) (~20 lignes — 4 sites raise utilisent `t_or_hardcoded` + le remap finding_keys dans la construction AuditBaseline).
- Locale : 4 nouvelles clés × 2 locales = 8 entries sous `compare.baseline_load.*`.

### Upgrade

```
pipx upgrade bodyguard-of-bits
```

**v0.7.x reste EOL** (déclaration formelle dans [SECURITY_FR.md](../SECURITY_FR.md) depuis v0.8.1).
**v0.6.x reste EOL** (déclaré en v0.7.2).

### Leçons

- **La liste "déféré à v0.10.0+" est un holding pattern utile, pas un cimetière.** Les deux items avaient été write-off comme future travail v0.10.0 en v0.9.1 ("zéro signal user"), mais l'estimation d'effort s'est révélée petite (~1.5 h total) et la campagne field test avait déjà fait le hard work de documenter les bugs reproductiblement. Ré-évaluer la liste déférée à chaque patch cycle coûte ~5 minutes et surface occasionnellement des wins "en fait on peut le faire maintenant".
- **L'évitement d'import circulaire via tiny shared modules** est cheap. `bob/_v090_renames.py` est 50 lignes, a zéro dépendance runtime, expose un dict et un helper. L'alias back-compat dans `runner.py` garde n'importe quel script out-of-tree fonctionnel. Pattern réutilisable pour toute future situation "deux consumers, ne peuvent pas s'importer".
- **Les pure transforms sont plus faciles à tester que les features wired-in**. `remap_finding_key` est une pure function 5-lignes — 18 tests parametrize couvrent chaque classe d'input raisonnable. Le test du baseline shim wired-in est alors un thin integration test au-dessus de la pure transform trusted.
- **Le release same-day v0.9.1 + v0.9.2 est fine** quand le travail est genuinely petit et indépendant. v0.9.1 a fixé un bug de code-correctness ; v0.9.2 a fermé deux gaps UX. Les combiner aurait muddied le message hotfix v0.9.1 (qui délibérément n'a PAS touché ces items pour que le fix F-3 soit le seul diff à reviewer).

---

## [v0.9.1] — 08-06-2026

**Hotfix de la régression UX message F-3 v0.9.0** surfacée par la campagne field test cross-distro.

### Le bug — reproduit 5/5 distros × 2 locales

Le ship F-3 v0.9.0 (retrait --json-v1) a ajouté ce raise à l'intérieur de `parse_args()` :

```python
elif arg == "--json-v1":
    from bob import i18n
    raise CLIError(i18n.t("cli.error.json_v1_retired"))
```

Mais `parse_args` tourne AVANT que `i18n.init()` soit appelée dans [bob/__main__.py](../bob/__main__.py) (l'init se passe après que les args CLI ont été parsés parce que la langue peut être contrôlée par `--lang=` / `--french`). Donc le lookup `i18n.t()` hit pré-init et surface le bracketed-fallback au user :

```
$ bob --json-v1
i18n.t() called before i18n.init() — returning key 'cli.error.json_v1_retired'
Error: [cli.error.json_v1_retired]
```

Au lieu du message actionnable que l'opérateur a besoin de savoir quoi faire.

**Reproduction field test** : la campagne cross-distro v0.9.0 a fait tourner le bug sur cinq distributions (Linux Mint 22.3 desktop, Debian 13 server, Kali Rolling, Linux Mint 22.3 server locale FR, Ubuntu 26.04 LTS locale FR). Le bracketed-fallback fire déterministiquement 5/5 distros × 2 locales (EN + FR) parce que c'est le lookup lui-même qui fail avant qu'une traduction puisse se produire — la locale est non pertinente.

### Le fix

Inline un string EN dans le raise `CLIError` :

```python
elif arg == "--json-v1":
    raise CLIError(
        "--json-v1 was retired in v0.9.0. Schema v2 is the only "
        "supported format (v2 has been the default since v0.7.0). "
        "See CHANGELOG.md v0.9.0 entry for the field-by-field "
        "migration table from v0.6.x v1 to v2."
    )
```

Cela match la convention utilisée par **chaque autre** raise `CLIError` dans [bob/cli.py](../bob/cli.py) — le fichier a 18 autres raises CLIError et toutes utilisent des littéraux anglais (`"--watch=N requires an integer ≥ 10"`, `"--diff specified more than once"`, `"-l/--log-days requires an integer ≥ 1"`, …). Le ship F-3 v0.9.0 était le seul consumer `i18n.t()` à l'intérieur de `parse_args` et était incohérent avec le pattern établi. Le fix restaure la cohérence.

Les clés locale désormais inutilisées `cli.error.json_v1_retired` (EN + FR) sont retirées de [bob/locales/{en,fr}.json](../bob/locales/en.json) puisqu'aucun call site ne les référence plus.

### Guards de régression

[tests/test_v091_cli_i18n_safety.py](../tests/test_v091_cli_i18n_safety.py) — 2 nouveaux tests :

- **`test_parse_args_does_not_call_i18n_t`** — AST scan sur le body de la fonction `parse_args()`. Walk chaque node en cherchant les nodes `Call` où la fonction est `i18n.t` (`Attribute(value=Name(id='i18n'), attr='t')`). Le test fail quand N'IMPORTE QUEL appel de ce type existe à l'intérieur de `parse_args`. Un futur contributeur qui ajoute un autre appel `i18n.t()` dans ce scope fait échouer le test avant que le message d'erreur user-facing ne dégrade. Le message de test pointe aussi vers l'alternative recommandée (`bob._i18n_safe.t_or_hardcoded(key, fallback)`) qui fallback vers la baseline EN quand i18n n'est pas initialisée.
- **`test_json_v1_retired_emits_actionable_message`** — guard direct qui appelle `parse_args(["--json-v1"])`, catche le `CLIError`, et asserte :
  * Le message ne match PAS le pattern bracketed-fallback (`startswith("[")` + `endswith("]")`)
  * Le message contient `"v0.9.0"` (pour que les users voient la fenêtre de retrait)
  * Le message contient `"json-v1"` ou `"schema"` (pour que les users voient le flag retiré ou son remplacement)

Les deux guards tournent en <1 ms — cheap à garder à HEAD pour toujours.

### Pourquoi c'est une v0.9.1 et pas une v0.10.0

Strictement parlant c'est un bug de code-correctness, pas un feature change. Le fix est un remplacement string inline de 6 lignes plus un guard de régression de 2 tests. Le bump de release surface (pyproject + manpage + CHANGELOG × 4 + memory) est le bulk du patch. v0.9.1 est le bon minor-bump parce que :

- Le behaviour user-visible change pour le même input (`bob --json-v1` montre maintenant du texte actionnable)
- Les clés locale `cli.error.json_v1_retired` sont retirées (un changement de wire surface contract pour quiconque scrape les fichiers locale programmatically, however unlikely)
- Le ship rapide du fix débloque les opérateurs qui hit le message F-3 pendant la migration

### v0.9.0 n'est PAS yanké

Le bug F-3 n'affecte que les users qui passent explicitement le flag retiré `--json-v1` (consumers JSON legacy v0.6.x). Le chemin audit golden (`sudo bob`, tous formats v2 / CSV / markdown / HTML, `--diff`, `--explain`, …) n'est pas affecté. Les users sur v0.9.0 qui rencontrent le bracketed-fallback peuvent soit upgrade vers v0.9.1 soit arrêter d'utiliser `--json-v1` (le flag est retiré de toute façon, donc l'action corrective est la même).

La procédure yank v0.8.2 ([[project_pypi_yank_procedure]]) est documentée et prête si un futur hotfix justifie réellement un yank — F-3 ne le justifie pas.

### Autres gaps i18n observés pendant la campagne field test (non fixés en v0.9.1)

Le field test a surfacé deux gaps i18n mineurs qui ne sont **PAS** fixés dans ce hotfix :

1. **Messages `BaselineLoadError` hardcoded anglais** ([bob/compare.py](../bob/compare.py)). Même sur systèmes FR, `sudo bob --diff=/tmp/nonexistent.json` montre `Erreur : Baseline file not found: ...` (le prefix "Erreur :" est FR via la clé locale `cli.error.prefix`, mais le body du message lui-même est anglais). Contrairement à F-3, ce raise se passe APRÈS que `i18n.init()` tourne (c'est dans le chemin audit, pas parse_args), donc il POURRAIT être proprement i18n'd. **Déféré à v0.10.0+** — actionable, lisible, zéro signal user.

2. **Bruit diff baseline cross-version sur les finding keys renommées D-1**. Observé sur Ubuntu 26.04 pendant le field test : un baseline écrit par v0.7.0 avait `iptables_nft.input_accept` / `iptables_nft.forward_accept`, et l'audit v0.9.0 émet `firewall_iptables.input_accept` / `firewall_iptables.forward_accept` (renommés en D-1). Le diff montre les 2 mêmes problèmes physiques sous-jacents comme *résolus* (vieille clé) ET *nouveaux* (nouvelle clé). C'est un comportement attendu documenté per le CHANGELOG v0.9.0 ("les entries ignore.yml référençant des finding keys renommées doivent être migrées à la main"), self-heal au 2ème audit post-upgrade, et a actuellement zéro signal user. **Déféré à v0.10.0+** — pourrait être résolu avec un baseline migration shim qui utilise `_RENAMED_SECTIONS_V090` comme reverse map au load time. À revisiter quand un user signale.

### Numbers

- **Tests 6210 → 6212** (+2 guards). 0 régression.
- 1 fichier code production modifié ([bob/cli.py](../bob/cli.py)) — 5 lignes changées.
- 2 fichiers locale modifiés ([bob/locales/{en,fr}.json](../bob/locales/en.json)) — 1 clé retirée chacun.
- 1 nouveau fichier test ([tests/test_v091_cli_i18n_safety.py](../tests/test_v091_cli_i18n_safety.py)).
- Toute la release surface (pyproject / manpages / shields / debian / rpm / CHANGELOG × 4 / TESTING / README_TECH × 2) bumpée.

### Upgrade

```
pipx upgrade bodyguard-of-bits
```

**v0.7.x reste EOL** (déclaration formelle dans [SECURITY_FR.md](../SECURITY_FR.md) depuis v0.8.1).
**v0.6.x reste EOL** (déclaré en v0.7.2).

### Leçons

- **Les tests unitaires mock-heavy ratent les bugs i18n pré-init**. Les tests F-3 v0.9.0 assertaient que la clé locale existait (`test_v082_items.py`) mais n'exerçaient jamais l'invocation CLI end-to-end. La campagne field test l'a chopé au premier run user-facing. Leçon : les appels `i18n.t()` pré-init ont besoin d'un guard statique explicite (AST scan), pas une assertion runtime qui dépend de l'ordre d'init.
- **Field test cross-distro = stress test cheap des assumptions locale**. La matrice 5-distros × 2-locales a surfacé ce bug déterministiquement — même root cause indépendamment de distro / locale. Cinq hosts suffisent ; le bug est dans le code path, pas l'environnement.
- **L'anglais hardcoded dans CLIError est une convention projet, pas une dette technique**. `bob/cli.py` a 19 raises `CLIError` ; 18 utilisent des littéraux anglais on purpose parce que la couche parsing est locale-init-naive by design. Le ship F-3 v0.9.0 était la seule exception qui cassait le pattern. Restaurer le pattern est le fix correct le plus simple.
- **Documenter les items "non fixés" dans le changelog**. Le gap BaselineLoadError EN et le diff noise cross-version sont des UX warts CONNUS surfacés par le field test. Les lister dans le changelog v0.9.1 évite le piège de "on a shippé un hotfix mais on n'a pas dit ce qu'on n'a délibérément pas fixé" — future-toi lit l'entry et sait ce qui reste sur la liste déférée.

---

## [v0.9.0] — 07-06-2026

**Première release v0.9.x — bundle BREAKING qui ferme le cleanup architectural déféré v0.7.0 → v0.8.x.**

Cette release ship les items BREAKING déférés depuis v0.7.0 : renumber + uniformité naming sections (D-1), fusion `_ALL_SECTIONS`/`_ALWAYS_ON_SECTIONS` (D-2), retrait `EXPLAIN_KEY_ALIASES` (D-3), retrait trap door `BOB_SANDBOX_LEGACY` (TD-1), retrait schéma legacy `--json-v1` (F-3), compare cross-machine `--diff [PATH]` (F-2), plus un bug fix bash completion compagnon de v0.8.2.

### D-1 BREAKING — 7 renames sections

Pre-v0.9.0 les noms de sections avaient drifté à travers l'historique v0.5.x-v0.8.x : collisions entre filterables et always-on (`docker_audit` vs always-on `docker`, `services_state` vs always-on `services`), suffixes redondants incohérents entre siblings (`cron_audit` à côté de `auditd` qui n'a pas de `_audit`), et noms trop génériques qui peuvent vouloir dire n'importe quoi (`rules` standalone peut être ufw, iptables, audit, sudoers, …).

Les 7 renames :

| Ancien           | Nouveau            | Raison                                                                  |
|------------------|--------------------|-------------------------------------------------------------------------|
| `cron_audit`     | `cron`             | Drop suffix `_audit` redondant (cf. `auditd`, `samba`)                  |
| `docker_audit`   | `docker_hardening` | Résout collision avec section always-on `docker`                        |
| `services_state` | `services_health`  | Résout collision avec section always-on `services`                      |
| `ports_analysis` | `ports`            | Drop suffix `_analysis` redondant                                       |
| `rules`          | `firewall_rules`   | `rules` standalone trop générique                                       |
| `iptables_nft`   | `firewall_iptables`| Unifie le namespace `firewall_*`                                        |
| `firewall_stack` | `firewall_drivers` | "drivers" décrit ce que le check audit (iptables vs nftables)           |

La migration touche les surfaces suivantes, toutes synchronisées dans cette release :

- [bob/runner.py](../bob/runner.py) — tuple `_SECTIONS` (post-D-2) porte les nouveaux noms ; chaque site `_sec(...)` et `emit_section(...)` migré ; nouveau dict `_RENAMED_SECTIONS_V090` + le fatal-migration-error path dans `validate_check_filters`.
- [bob/checks/*.py](../bob/checks/) — chaque site `key="<old>.X"` et `t("<old>.X")` migré dans `cron_audit.py`, `docker_audit.py`, `services_state.py`, `iptables_nftables.py`, `firewall_stack.py`, et les clés `rules.X` dans `firewall.py`. Noms de fichiers gardés tels quels — les chemins module internes ne sont pas API publique, les renommer forcerait du noisy git history sans bénéfice user.
- [bob/explain.py](../bob/explain.py) — entries `EXPLAIN_KEYS` renommées (168 clés).
- [bob/data/cis_refs.json](../bob/data/cis_refs.json) — 20 clés CIS reference renommées.
- [bob/data/profiles/{container,desktop,workstation}.conf](../bob/data/profiles/) — overrides sévérité profile + skip list section du profile `container`.
- [bob/data/bob.bash-completion](../bob/data/bob.bash-completion) — `_SECTIONS` list bumpée pour matcher `_ALL_SECTIONS`.
- [bob/locales/{en,fr}.json](../bob/locales/en.json) — namespaces root, `sections.X`, `sections.descriptions.X`, et entries `explain.X` renommées sous les 7 prefixes. Deux nouvelles clés locale : `cli.runner.section_renamed` (message migration per-token) + `cli.runner.section_renamed_fatal` (pointer one-shot vers la table de migration).
- [bob/scoring.py](../bob/scoring.py) + [bob/json_output.py](../bob/json_output.py) + [bob/domain_scores.py](../bob/domain_scores.py) — refs clé hardcoded migrées.
- ~167 lignes à travers 14 fichiers tests updates par mechanical prefix migration.

Le migration error path dans `validate_check_filters` fire AVANT le générique "no match / did you mean" path pour que les users voient le remplacement canonique précis (`cron_audit` → `cron`) au lieu d'une fuzzy `difflib` guess. Mirror path pour `--skip`. Les titres section headers (rendus locale, affichés pendant l'audit) sont inchangés ; la surface BREAKING est le nom de token script-visible uniquement.

#### Fix sémantique validateur (effet de bord D-1)

Après l'ajout de `firewall_iptables` / `firewall_rules` / `firewall_drivers` à `_ALL_SECTIONS`, le token `firewall` matche un filterable via la règle `startswith` existante, ce qui silenceait le warning "no effect" que les operateurs attendent légitimement pour `--skip=firewall` (la section always-on). La boucle skip-token dans `validate_check_filters` check maintenant **exact always-on matches** AVANT les prefix filterable matches. Même fix appliqué pour les prefixes `--check=docker` et `--check=services` qui ont maintenant aussi des companions filterables.

### D-2 internal — fusion `_ALL_SECTIONS` + `_ALWAYS_ON_SECTIONS`

Pre-v0.9.0, deux tuples parallèles (`_ALL_SECTIONS` pour filterable et `_ALWAYS_ON_SECTIONS` pour inconditionnel) devaient être maintenus en sync manuellement : ajouter une section voulait dire se rappeler quel tuple update, et la logique de validation + le rendering `bob --check=list` devaient unir les deux.

Le nouveau [`_SECTIONS: tuple[_Section, ...]`](../bob/runner.py) est une source unique de vérité où chaque entry porte un flag boolean `always_on`. Les legacy `_ALL_SECTIONS` / `_ALWAYS_ON_SECTIONS` sont des vues dérivées construites une fois à import time. External consumers ([bob/__main__.py](../bob/__main__.py) + 3 fichiers tests) gardent les noms legacy — les vues dérivées sont des tuples immutables computés une fois à import. New code devrait consommer `_SECTIONS` directement pour accéder au flag `always_on`.

### D-3 cleanup — `EXPLAIN_KEY_ALIASES` retiré

Pre-v0.9.0, `EXPLAIN_KEY_ALIASES` portait un seul entry live (`services_state.service_inactive` → `services_state.enabled_inactive`, devenu `services_health.*` après le rename D-1) qui était un pont sur un drift source-side v0.5.5 : `services_state.py` émet `services_state.service_inactive` comme sa finding key, mais l'entry EXPLAIN_KEYS + le bloc locale étaient nommés `enabled_inactive`. Le D-3 warning de déprécation v0.8.2 a annoncé le retrait pour v0.9.0.

v0.9.0 D-3 résout le drift à la source au lieu de le bridger :
- L'entry EXPLAIN_KEYS a été renommée `services_health.enabled_inactive` → `services_health.service_inactive` pour matcher ce que `services_state.py` émet
- Le namespace locale `explain.services_health.enabled_inactive` → `service_inactive` (EN + FR)
- Entry [bob/data/cis_refs.json](../bob/data/cis_refs.json) renommée (duplicate causé par mon mass-pass de rename D-1 dédupliqué)
- `EXPLAIN_KEY_ALIASES = {}` (dict gardé vide pour qu'un futur rename ait un migration path one-line)
- Machinery `_warn_alias_deprecation` + `_WARNED_ALIASES` retirée
- Les 4 tests deprecation v0.8.2 dans [tests/test_v082_items.py::TestExplainKeyAliasDeprecation](../tests/test_v082_items.py) retirés (le dict est vide, la machinery est gone)

### TD-1 BREAKING — trap door `BOB_SANDBOX_LEGACY=1` retiré

Pre-v0.9.0, l'env var bypassait le sandbox subprocess (spawn) et exécutait les plugins dans le processus parent avec builtins complets. Un WARNING stderr voyant + log CRITICAL firait à chaque audit qui entrait réellement en legacy mode, by design assez voyant pour que personne ne puisse l'utiliser en prod sans le remarquer.

Le trap door a été annoncé pour retrait dans le ship v0.7.0 + [SECURITY_FR.md](../SECURITY_FR.md) depuis v0.8.0. v0.9.0 TD-1 retire :

- Helper static `SandboxRunner._legacy_active()`
- Helper static `SandboxRunner._emit_legacy_warning()`
- Méthode `SandboxRunner._run_legacy()` (path exec in-process)
- Les branches `if self._legacy_active():` dans `__init__` et `run`

Set l'env var n'a maintenant aucun effet ; les plugins s'exécutent toujours dans le subprocess spawn. [SECURITY.md](../SECURITY.md) + [SECURITY_FR.md](../SECURITY_FR.md) mises à jour pour barrer l'entry et marquer la fenêtre de retrait.

Deux retirement guards dans [tests/test_plugin_sandbox.py::TestLegacyTrapDoorRetired](../tests/test_plugin_sandbox.py) :

- `test_legacy_env_var_has_no_effect` — set `BOB_SANDBOX_LEGACY=1`, run un plugin qui aurait réussi sous legacy mode (importe `subprocess`), asserte que l'import fail parce que le sandbox le bloque
- `test_legacy_active_helper_removed` — `hasattr(SandboxRunner, "_legacy_active")` + `_run_legacy` doivent être False tous les deux

### F-3 BREAKING — schéma legacy `--json-v1` retiré

Pre-v0.9.0, `--json-v1` opt-in au layout JSON v0.6.x (`schema_version="1"`) pour les consumers qui n'avaient pas migré vers v2. v2 est le défaut depuis v0.7.0 (4 majeures) et v0.6.x est EOL depuis v0.7.2 (5 majeures) ; quiconque lit toujours v1 n'a pas updaté son pipeline depuis 6+ mois.

v0.9.0 F-3 retire :

- Constantes `SCHEMA_V1_REQUIRED_KEYS` + `SCHEMA_V1_FULL_KEYS` de [bob/json_output.py](../bob/json_output.py)
- Helpers builders `_build_v1` + `_populate_v1_full_blocks` (~170 lignes)
- Le dispatch `schema_version == "1"` dans `build_json_data()`
- `SUPPORTED_SCHEMA_VERSIONS = frozenset({"2"})`
- Field `AuditConfig.json_v1`
- `--json-v1` de [bob/data/bob.bash-completion](../bob/data/bob.bash-completion) `long_opts`
- L'option `--json-v1` du help text

Passer `--json-v1` raise maintenant un `CLIError` (locale key `cli.error.json_v1_retired`, EN + FR) pointant vers le guide de migration CHANGELOG. Tests pinant le contrat baseline v1 : [tests/test_json_schema.py](../tests/) supprimé entièrement (~330 lignes) ; 5 tests v1-spécifiques dans `test_t11_t26_v081.py` + `test_json_schema_v2.py` retirés ; 1 entry retirée de `test_v082_bash_completion.py::TestLongOptsPresence` parametrize.

#### Table de migration field v1 → v2

| Field v1            | Équivalent v2                                                       |
|---------------------|---------------------------------------------------------------------|
| `timestamp`         | `timestamp_utc` (renommé, signale encodage UTC — B-3 en v0.7.0)     |
| `network_context`   | `network_context` dict dans les deux modes (était str en v1 short, dict en v1 full — fix A-2 P1) |
| `firewall_stack`    | `firewall_drivers` (BREAKING via D-1 — renommé en v0.9.0)           |
| —                   | `info_count` ajouté au top level (B-7 en v0.7.0)                    |
| —                   | Bloc `posture_escalation` ajouté (A-4 en v0.7.0)                    |
| —                   | `open_ports_all` (full only — B-5 en v0.7.0)                        |
| —                   | `deductions_raw` (full only — B-4 en v0.7.0)                        |
| `domain_scores[d]`  | `domain_scores[d]` inclut maintenant le count `deductions` (B-6)     |
| `risk`              | inchangé — dérivé de `engine.level` (score-only)                    |
| `posture_escalation.score_level` | nouveau — expose le baseline non-escaladé pour les consumers qui ont besoin des deux vues |

### F-2 NEW — compare cross-machine `--diff [PATH]`

Pre-v0.9.0, le flag `--diff` comparait l'audit courant contre le baseline local auto-managé à `~/.config/bob/last_baseline.json`. Utile pour "qu'est-ce qui a changé depuis mon dernier audit sur cet host", mais pas moyen de comparer contre un fichier baseline arbitraire (cross-machine, historique, prod-vs-staging).

v0.9.0 F-2 ajoute un argument PATH optionnel :

```bash
sudo bob --diff                            # comportement v0.8.x : load baseline local auto-managé
sudo bob --diff=/path/to/baseline.json     # NEW : compare contre fichier arbitraire
sudo bob --diff /backup/server-A.json      # NEW : équivalent space-separated
```

Les deux syntaxes (`--diff=PATH` et `--diff PATH`) sont supportées, miroir de `--watch[=N]`. Le bare `--diff` / `-D` garde la sémantique v0.8.x. La forme space a un guard peek-ahead pour que `sudo bob --diff --verbose` garde `--verbose` comme le flag suivant, pas comme un path baseline.

#### Implémentation

- [bob/cli.py](../bob/cli.py) — nouveau field `AuditConfig.diff_baseline_path: Path | None` ; paths de parsing `--diff=PATH` et `--diff PATH`
- [bob/compare.py](../bob/compare.py) — nouvelle exception `BaselineLoadError` ; `load_baseline(path, strict=True)` raise sur missing/broken file + sur `schema_version="1"` legacy. Défaut `strict=False` préserve le comportement silencieux v0.8.x pour bare `--diff`.
- [bob/compare.py::AuditBaseline](../bob/compare.py) — nouveau field `hostname: str | None`. `build_baseline()` appelle `socket.gethostname()` pour le populer. Les baselines pre-v0.9.0 sans le field ne causent pas de notice au load.
- [bob/__main__.py](../bob/__main__.py) — quand `config.diff_baseline_path` est set, appelle `load_baseline(path, strict=True)` ; sur `BaselineLoadError`, émet le message d'erreur locale-préfixé et exit avec `EXIT_ERROR`. Notice cross-machine : si le `hostname` enregistré diffère de `socket.gethostname()`, print `t("compare.cross_machine_notice", baseline_host=..., current_host=...)` avant l'affichage delta.
- [bob/data/bob.bash-completion](../bob/data/bob.bash-completion) — nouvelle filename completion `--diff=PATH` et `--diff PATH` (`compgen -f -- "${val}"` + `compopt -o filenames`).
- [man/bob.1](../man/bob.1) — section `.SS Comparison and history` mise à jour avec le nouvel argument optionnel + exemple usage cross-machine.

#### Tests

17 nouveaux tests dans [tests/test_v090_diff_baseline_path.py](../tests/test_v090_diff_baseline_path.py) :

- `TestCLIDiffPathParsing` — bare `-D` / `--diff`, `--diff=PATH`, `--diff PATH`, peek-ahead does-not-consume-flag-token, value empty rejeté, `--diff` dupliqué rejeté
- `TestLoadBaselineStrict` — file missing en strict raise avec path dans message, file missing non-strict return None, JSON invalide en strict raise, `schema_version="1"` en strict raise avec "v0.6.x" dans message, baselines v0.7.x–v0.8.x (sans field `schema_version`) load proprement sous strict
- `TestHostnameCapture` — roundtrip save→load préserve hostname, baselines pre-v0.9.0 load avec `hostname=None`, `build_baseline` capture le vrai hostname

### Bug fix — `bob --check=<TAB><TAB>` sans sudo

Compagnon du walk-back guard sudo-dispatcher v0.8.2. v0.8.2 a fixé le cas où `sudo bob --check=<TAB>` retournait zéro candidat parce que le sudo dispatcher invokait `_bob` avec `$prev` mis au littéral `=`. Le cas compagnon : sous invocations non-sudo, certaines versions de bash placent le curseur de completion sur le token littéral `=` (donnant `cur="="`, `prev="--check"`) au lieu d'un trailing empty word ; la branche `prev=="--check"` existante runnait alors `compgen -W "list ${_SECTIONS}" -- "="` qui retourne zéro parce qu'aucun nom de section ne commence par `=`.

Le fix est un companion guard 3-lignes en haut de `_bob` :

```bash
if [[ "${cur}" == "=" ]]; then
    cur=""
fi
```

Mirror du walk-back v0.8.2. Après ça, `bob --check=<TAB><TAB>` (non-sudo) restaure l'affichage de liste TAB×2. Vérifié sur 4 cas (sudo + non-sudo × empty-cur + cur="=") dans les tests fonctionnels bash completion existants.

### Numbers

- **Tests 6246 → 6210** (net −36) :
  - −53 : fichier baseline v1 `test_json_schema.py` (~330 lignes) + 5 tests v1-spécifiques dans `test_t11_t26_v081.py` + `test_json_schema_v2.py` + 4 tests deprecation-warning v0.8.2 (retirés avec la machinery alias) + 1 entry parametrize `--json-v1`
  - +17 : nouveaux tests F-2 dans `test_v090_diff_baseline_path.py`
- 0 régression.
- Code production : ~600 lignes changées à travers `bob/runner.py`, `bob/cli.py`, `bob/compare.py`, `bob/json_output.py`, `bob/_sandbox.py`, `bob/explain.py`, `bob/__main__.py`, `bob/scoring.py`, `bob/domain_scores.py`, `bob/data/bob.bash-completion`, et 6 fichiers `bob/checks/*.py`.
- Locale : 167+ migrations clé dans `bob/locales/{en,fr}.json` + 3 nouvelles clés (`cli.runner.section_renamed`, `cli.runner.section_renamed_fatal`, `cli.error.json_v1_retired`, `compare.cross_machine_notice`) × 2 locales.

### Upgrade

```bash
pipx upgrade bodyguard-of-bits
```

Les users avec scripts utilisant `--check=<nom_legacy>`, `--skip=<nom_legacy>`, `--json-v1`, ou `BOB_SANDBOX_LEGACY=1` doivent migrer per les tables ci-dessus :

- **Scripts** : `s/--check=cron_audit/--check=cron/`, etc. Le migration error path pointera vers le remplacement canonique à la première invocation échouée si tu en rates.
- **Consumers JSON** : rewrite pour lire le schéma v2. Les fields renommés et le nouveau bloc `posture_escalation` sont les points pratiques de migration.
- **Authors de plugins reposant sur `BOB_SANDBOX_LEGACY=1`** : l'env var est ignorée. Rework le plugin pour utiliser la surface API sandbox-allowed, ou run hors de `bob` (ex. comme un cron job séparé).
- **Entries `ignore.yml`** référençant les finding keys renommées (`cron_audit.pipe_to_shell` → `cron.pipe_to_shell`, etc.) doivent être migrées à la main. Pas d'auto-traduction ; les clés font silently no-op jusqu'à correction.

**v0.7.x reste EOL** (déclaration formelle dans [SECURITY_FR.md](../SECURITY_FR.md) depuis v0.8.1).
**v0.6.x reste EOL** (déclaré en v0.7.2).

### Déféré à v0.9.1

- **D-4** sub-checks granulaires (ex. `ssh.x11_forwarding` → `ssh.x11.forwarding.server` + `.client`) — requiert passe audit sub-agent pour identifier les candidats + écrire le guide de migration. Le quota sub-agent était le blocker au cut v0.9.0.
- **Parallel checks** via `concurrent.futures.ThreadPoolExecutor` (cible : ~30 s → 5–10 s sur audits multi-core) — même blocker audit sub-agent (invariants threading + discovery race condition).

### Leçons

- **Mechanical prefix renames à scale** (167 lignes × 14 fichiers tests + 88 lignes × 6 fichiers source) sont mieux faits avec un single Python script sur `re.sub(rf'"{old}\.', f'"{new}.', text)`. La boucle d'itération 5-seconde catche le drift dans les strings multi-lignes que le hand-Edit raterait.
- **Mass-rename dégât collatéral sur les migration maps documentées** — le même regex qui rename le codebase rename aussi la migration map elle-même (ex. `EXPLAIN_KEY_ALIASES`, `_RENAMED_SECTIONS_V090`) où les mappings old → new vivent comme string literals. Toujours ré-instaurer ces maps manuellement après la passe mécanique.
- **Validateurs cross-cutting ont besoin de re-ordering** quand les namespaces sections fusionnent. L'ordering `_matches_filterable` / `_matches_always_on` tenait pour v0.5.x–v0.8.x parce que les namespaces étaient disjoints. Les renames D-1 v0.9.0 ont créé de l'overlap (`firewall` matchait les deux via prefix), et le test a surfacé la régression immédiatement.
- **Mode strict pour les loaders explicit-path** — pour tout flag `--option PATH` qui load un file, le défaut silent-fallback est wrong quand le user a explicitement passé un path. v0.8.x `load_baseline()` retournait None sur erreur ; v0.9.0 ajoute `strict=True` pour le cas explicit-path, miroir de comment `open(path)` raise au lieu de retourner None sur missing.

---

## [v0.8.4] — 06-06-2026

**Dernière release v0.8.x — batch cleanup avant le bundle BREAKING v0.9.0.**

### Retrait dead code — is_unit_enabled

[bob/checks/_run.py](../bob/checks/_run.py) — `is_unit_enabled(name, timeout)` ajouté en v0.5.0 (refactor Phase 1 #7) comme miroir symétrique de `is_unit_active` et documenté dans la liste release-monitoring comme "no immediate consumer — to be reviewed each v0.5.x release". 7 mois et 4 minor versions plus tard (v0.5.x → v0.6.x → v0.7.x → v0.8.x), le grep est inchangé :

- Zéro consumers dans `bob/`
- Zéro références dans `tests/`
- `services.py::_detect_single_unit_state` continue d'utiliser son propre appel `_run` comme conçu au ship time v0.5.0

L'argument symétrie d'API n'a pas tenu — la fonction est retirée. Les entrées CHANGELOG historiques (table ship v0.5.0 + section détail #7 + mirrors FR + détail FULL changelog) sont préservées tel quel. Elles décrivent fidèlement ce qui a shippé à l'époque ; réécrire l'historique obscurcirait le fait que l'API a existé et a été délibérément retirée après observation.

Cela ferme la liste release-monitoring v0.5.0 (les 2 entrées décidées) :

- `is_unit_enabled` — **DELETED** en v0.8.4 (7 mois sans consumer = signal suffisant que l'hypothèse symétrie-API n'a pas tenu)
- Paramètre `width=62` de `bob.output.print_titled_box` — **KEPT off-monitor** en v0.8.4 (4 call sites utilisent le défaut ; 7 mois de stabilité promeut le paramètre de "spéculatif" à "stable de facto" ; le retirer casserait l'API publique sans gain)

### Nouveau tutoriel — DOCUMENTS/TUTORIAL{,_FR}.md

Walkthrough end-to-end premier-utilisateur, 269 lignes par locale (parité EN + FR), couvrant :

1. Ce que BOB fait (une phrase) + ce que BOB n'est PAS (framing carryover de v0.8.0 A2)
2. `pipx install` + le gotcha PATH `sudo bob` + résolution `--install-completion`
3. Premier audit + lecture du score (niveau, clé, footer hypothèses)
4. `--explain KEY` — picker / list / tab-completion
5. Contrat `--fix` dry-run + `--fix --apply`
6. Sélection profile — server / desktop / workstation / container
7. No-noise path — `--ignore` / `--unignore` / `--show-ignored`
8. Automation — `--install-cron` + `--webhook=` + smoke `--test-webhook`
9. Workflows baseline-driven — `--diff` / `--history` / `--watch`
10. Consumers machine — JSON / CSV / Markdown / HTML + codes de sortie `-q` + `--target=N`
11. Scénarios courants — mode silencieux CI, target floor, audit français
12. Pointers vers README_TECH / AUTOMATION / SECURITY / CHANGELOG

Linké depuis [README.md](../README.md) + [README_FR.md](../README_FR.md) sections "See also" / "Voir aussi" en première entrée, pour qu'un reader premier-fois atterrisse ici avant la référence technique.

C'était l'item `tutorial` déféré du backlog v0.9.0. Il est déplacé dans v0.8.4 parce que c'est de la documentation pure avec zéro surface code — pas de raison de parker de la documentation derrière un bundle BREAKING.

### Fermeture roadmap — compare-breakdown-diff killed

[[project_future_compare_breakdown_diff]] (memory) — roadmap feature ouverte en v0.3.0 (2026-05-08) pour ajouter diff per-key des déductions dans `bob compare`. Statut au ship time v0.8.4 :

- Ouvert depuis v0.3.0
- Zéro signal user à travers 5 majeures (v0.4 / v0.5 / v0.6 / v0.7 / v0.8)
- Le `deduction_delta` global existant suffit pour le cas d'usage réel (pas une seule plainte user de la forme "je vois -5 entre 2 audits mais je ne sais pas d'où ça vient")
- Effort estimé : baseline schema change BREAKING + logique diff + UI compare = ~6-8h. Non justifié sans demande concrète.

Pattern : si une feature reste dormante 5 majeures sans signal, le marché a parlé — tuer plutôt que conserver indéfiniment. Le memory est marqué closed ; rouvrir requiert un signal user explicite.

### Numbers

- **Tests 6246 → 6246** (pas de delta — le helper retiré n'avait pas de test coverage à supprimer). 0 régression.
- 1 fichier code production modifié ([bob/checks/_run.py](../bob/checks/_run.py)) — 10 lignes supprimées.
- 2 nouveaux docs ([DOCUMENTS/TUTORIAL.md](../DOCUMENTS/TUTORIAL.md) + [DOCUMENTS/TUTORIAL_FR.md](../DOCUMENTS/TUTORIAL_FR.md)) — 540 lignes ajoutées au total.
- 2 README mis à jour pour le nouveau lien tutorial.
- 4 surfaces changelog + memory updates + TESTING.md + man pages + debian + rpm bumpés.

### Upgrade

```
pipx upgrade bodyguard-of-bits
```

**v0.7.x reste EOL** (déclaration formelle dans [SECURITY_FR.md](../SECURITY_FR.md) depuis v0.8.1).
**v0.6.x reste EOL** (déclaré en v0.7.2).

### Suite — bundle BREAKING v0.9.0

v0.8.x est **fermée** — les futurs patches v0.8.x ne shipperont que pour les régressions sécurité. La prochaine release active est v0.9.0, planifiée comme un seul bundle BREAKING :

- **D-1** sections renumber + uniformité naming `emit_section()`
- **D-2** fusion `_ALL_SECTIONS` + `_ALWAYS_ON_SECTIONS` en un tuple unique avec un flag `is_always_on`
- **D-4** sub-checks granulaires (rename keys — casse les entries `~/.config/bob/ignore.yml` sur les systèmes avec listes de suppression custom)
- **Retrait** trap door `BOB_SANDBOX_LEGACY=1` (documenté dans SECURITY.md comme env var back-compat pour exécution plugin in-process)
- **Parallel checks** via `concurrent.futures.ThreadPoolExecutor` pour les audits domain indépendants (cible : ~30s → 5-10s sur multi-core)
- **`--diff <baseline.json>`** compare cross-machine (additif au flow `~/.config/bob/baseline.json` local)

Le bundle est groupé parce que chaque item seul est trop petit pour ship un bump majeur, alors que les shipper piecemeal forcerait les users à absorber 6 changements BREAKING à travers 6 minor versions.

### Leçons

- **La politique release-monitoring a fonctionné** — 7 mois de grep patient + un critère de deletion clair ("zéro consumer + zéro signal" = remove) ont produit un retrait propre sans surprises.
- **Fermer les features dormantes a besoin d'une politique explicite** — garder `project_future_compare_breakdown_diff` indéfiniment sur la liste maybe-someday coûtait du overhead cognitif à chaque planning de release. La règle 5-majeures-dormancy → kill est claire.
- **Le travail pure-docs appartient aux patch releases** — parker le tutorial derrière le bundle BREAKING v0.9.0 l'aurait retardé de 2-3 semaines sans justification code-coupling.

---

## [v0.8.3] — 06-06-2026

**HOTFIX — le chemin audit de v0.8.2 crashait avec `UnboundLocalError` sur chaque invocation autre que `--test-webhook`.**

### Root cause

Le handler `--test-webhook` v0.8.2 faisait `from bob.config import UserConfig` *à l'intérieur* de `main()` ([bob/__main__.py:213](../bob/__main__.py#L213)). L'analyseur de scope Python a vu la déclaration `from` locale et a traité `UserConfig` comme nom function-local pour tout le body `main()` — même sur les code paths qui n'atteignaient jamais l'import local. Le chemin audit à `user_config = UserConfig.load()` (ligne 298 au ship time) raisait alors :

```
Fatal error: cannot access local variable 'UserConfig' where it is not associated with a value
```

sur **chaque** invocation `bob` régulière qui n'entrait pas dans la branche `--test-webhook`. Le même pattern de shadowing existait pour `os` et `traceback` à l'intérieur du `except` handler top-level ligne 585.

### Pourquoi les tests unitaires l'ont raté

La suite 6244 tests de v0.8.2 n'a pas chopé le bug parce que les tests exercent soit :

- la branche `--test-webhook` directement (qui **passe** par l'import `from` local, donc `UserConfig` est bound et résout), soit
- le chemin audit avec `UserConfig.load` mocké, donc le nom résout via le décorateur mock sans hitter l'unbound local

Le guard d'integration `smoke-plugin-on-CI` a chopé ça sur l'invocation live `bob --offline -v` — mais seulement **après** que `v0.8.2` ait déjà été publié sur PyPI.

### Fix

[bob/__main__.py](../bob/__main__.py) — 3 changements minimaux :

- Suppression du `from bob.config import UserConfig` redondant à l'intérieur de `main()` (l'import module-level ligne 26 était déjà in-scope avant v0.8.2 ; le re-import local a été ajouté par le ship `--test-webhook` et l'a shadow-é)
- Suppression du `import os` redondant dans le `except` handler ligne 585 (le `import os` module-level en haut du fichier était déjà in-scope ; le re-import local le shadow pour le reste de `main()`, même si dans ce cas spécifique la seule référence `os.<x>` venait **après** l'import local, donc le bug était latent plutôt qu'actif)
- Promotion de `import traceback` à un import module-scope (était seulement importé dans la branche `BOB_DEBUG` — module-scope est l'emplacement correct)

### Guard de régression

[tests/test_v083_main_scope_guard.py](../tests/test_v083_main_scope_guard.py) — 2 tests, analyse statique via `ast` :

- `test_main_function_does_not_shadow_module_scope_imports` : pour chaque nom importé au module scope de `bob.__main__`, scanne `main()` et asserte qu'aucune déclaration `from`/`import` locale ne rebind le même nom
- `test_user_config_resolves_at_module_scope` : guard direct que `UserConfig` survit comme binding module-level (`hasattr(bob.__main__, "UserConfig")`)

Un futur contributeur qui ajoute un autre defensive re-import dans `main()` fait échouer le premier test **avant** que le chemin audit ne crash pour les users.

### Numbers

- **Tests 6244 → 6246** (+2 guard). 0 régression.
- 1 fichier de code production modifié ([bob/__main__.py](../bob/__main__.py)).
- 1 nouveau test file ([tests/test_v083_main_scope_guard.py](../tests/test_v083_main_scope_guard.py)).
- Les 4 surfaces changelog + memory note + cette section mises à jour pour traceability.

### Upgrade

**v0.8.2 est cassé sur PyPI** (chemin audit crash sur chaque invocation régulière). Les users sur v0.8.2 doivent upgrade immédiatement :

```
pipx upgrade bodyguard-of-bits
```

**v0.7.x reste EOL** (déclaration formelle dans [SECURITY_FR.md](../SECURITY_FR.md) depuis v0.8.1).
**v0.6.x reste EOL** (déclaré en v0.7.2).

### Leçons

- Les tests unitaires qui mockent `UserConfig.load` masquent les bugs de name-binding — le code path du chemin audit s'exécute, mais `UserConfig` résout via le namespace patch du décorateur mock, pas via les règles de binding function-local.
- Un `from X import Y` function-local est **légal** mais transforme `Y` en nom function-local pour le **body entier** de la fonction, y compris les code paths au-dessus de l'import local. Quand `Y` était déjà importé au module scope, la déclaration locale le shadow partout et crée un trap `UnboundLocalError`.
- Les guards statiques (`ast.walk` sur un body de fonction) catch la classe de bug sans avoir besoin d'un exercise runtime — préféré aux subprocess smoke tests pour un feedback prédictible + rapide.

---

## [v0.8.2] — 06-06-2026

**Patch conservative-bundle — 6 items user-facing + DX, pas de BREAKING.**

Nettoie la dette DX des migrations i18n + bash-completion + helper-text v0.7.x / v0.8.0-v0.8.1. Ferme le gap UX `--test-webhook` (la story webhook v0.7.0 a shippé sans commande smoke standalone). Met en place le cleanup architectural v0.9.0 (D-1 / D-2 / D-4 + retrait `BOB_SANDBOX_LEGACY` + parallel checks + `--diff <baseline.json>`) via le warning de déprécation D-3 + le linter locale qui catch les classes de drift exposées par les passes audit 7 + 8.

6198 → **6244 tests** (+46 net). 0 régression.

### Bash completion v0.8.2

[bob/data/bob.bash-completion](../bob/data/bob.bash-completion) — 4 améliorations + un guard de sync + un fix sudo-dispatcher.

- **Sync `_SECTIONS` + `_EXPLAIN_KEYS` avec runtime**. Liste sections déjà sync au ship time ; liste explain-keys (168 entries) insérée fresh depuis `bob.explain.EXPLAIN_KEYS` via le scaffold regenerate pour que tout drift ultérieur surface en CI.
- **Completions value `--unignore=KEY` / `--ignore=KEY` / `--explain KEY`**. v0.8.1 T57 a ajouté `--unignore` mais n'a pas étendu le script completion. v0.8.2 ajoute handlers dédiés pour les formes space et `=`, sourcés du catalogue canonique 168-keys EXPLAIN_KEYS.
- **`--json-v1` + `--test-webhook` dans `long_opts`**. Le premier était un ship Phase 2 v0.7.0 ; le second est nouveau ce cycle.
- **Commentaire alias `workstation` stale retiré**. Pre-v0.8.2 le commentaire de la completion `--profile` claimait *"workstation est un alias backward-compat loading desktop"* ; le retrait v0.8.1 a rendu ça mensonger. Maintenant : *"workstation est désormais un profil FIRST-CLASS distinct de desktop"*.
- **Fix sudo-dispatcher `=`** (commit `2a62bf3`). Régression user-reportée : `sudo bob --check=s<TAB>` retournait zéro candidat alors que `bob --check=s<TAB>` (sans sudo) marchait. Root cause : le dispatcher sudo de bash-completion (`_command_offset`) invoke `_bob` avec `$prev` mis au littéral `=` au lieu du nom d'option quand `=` reste dans COMP_WORDBREAKS — toutes les combinaisons bash + bash-completion ne le strippent pas via `_init_completion -s`. Aucune des branches par-option `prev == "--check"` / `--ignore` / `--unignore` / `--explain` ne matchait, donc la fonction tombait sur le default long_opts qui ne s'applique pas à une valeur partielle comme `"s"`. Fix : guard défensif 3-lignes en tête de `_bob` qui détecte `prev == "="` et récupère le nom d'option réel en remontant deux positions dans COMP_WORDS. Restaure le value-narrowing pour chaque `--<option>=<partial>` sous sudo ET sans sudo.

[tests/test_v082_bash_completion.py](../tests/test_v082_bash_completion.py) ship 21 tests sur 6 classes : guards de sync (parité set), présence long-opts (parametrized), invocations bash fonctionnelles (source le script dans sub-bash + assert COMPREPLY).

### Consolidation i18n — bob/_i18n_safe.py

Pre-v0.8.2, 4 modules définissaient chacun leur propre `_fallback_t` avec comportements drift (`markdown_output` skippait `.format()`, `html_output` conditionnait sur kwargs, `config`/`webhook` formataient toujours). Trois implémentations subtilement différentes pour la même intention.

[bob/_i18n_safe.py](../bob/_i18n_safe.py) — nouveau module — expose une factory unique :

```python
from bob._i18n_safe import make_fallback_t
_fallback_t = make_fallback_t(_FALLBACK_LABELS)
```

Le body factory essaie toujours `.format(**kwargs)` + retourne le template brut sur `KeyError` / `IndexError`. Templates sans `{}` passent through unchanged. Plus `t_or_hardcoded(key, fallback)` hoisted out de `__main__.py` (T60 v0.8.1 l'avait introduit comme def locale).

Tests pin chaque contract + cross-module assertion que les 5 modules migrés importent + appellent la factory.

### Commande smoke `--test-webhook`

[bob/webhook.py::test_webhook](../bob/webhook.py) — nouvelle fonction publique. POST un payload minimal avec champs `test=true` + `tag="bob_smoke_test"` (generic) ou attachment Slack-formatted (slack). Réutilise chaque guard URL-validation de `send_webhook` : scheme + plain-http + escape hatch `BOB_WEBHOOK_ALLOW_INSECURE` + redaction `WebhookError` via `redact_url_credentials` (T74 v0.8.1).

Wire dans CLI à [bob/__main__.py:190-220](../bob/__main__.py#L190). Le flag `--test-webhook` bypass `require_root()` parce que le smoke est une sonde réseau + sérialisation JSON, pas d'inspection système — pas d'audit, pas de sudo. Résolution URL mirror le path audit-time. 4 nouvelles clés locale EN+FR sous `cli.test_webhook.*`.

Pre-v0.8.2 la seule façon de valider une config `bob --webhook=URL` fraîche était de lancer un audit complet (~30 s + sudo). Le gap DX était particulièrement douloureux pour les setups cron.

### Descriptions sections `--check=list`

[bob/__main__.py:115-152](../bob/__main__.py#L115) — la boucle rendering `--check=list` résout maintenant une description par section via `i18n.t(f"sections.descriptions.{name}")`. Description manquante → fallback au nom de section bare.

44 descriptions shippent dans EN + FR sous nouveau namespace `sections.descriptions.*`. 1 ligne par section, ≤ 80 chars typique. Couvre les 34 sections filterables + 10 always-on.

Tests pin la parité namespace ↔ runtime sections — nouvelle section sans locale wiring casse CI.

### Warning déprécation D-3 sur EXPLAIN_KEY_ALIASES

[bob/explain.py:368-432](../bob/explain.py#L368) — `normalize_key()` émet maintenant un `logger.warning` one-shot quand il résout un alias :

```
DEPRECATION: explain key 'services_state.service_inactive' is a legacy alias for
'services_state.enabled_inactive' — the alias is scheduled for retrait in v0.9.0.
Migrate scripts, saved profiles, and ignore.yml entries to the canonical name.
```

Logger-only (surface dans `--detailed` `.log` + journald cron) sans polluer les outputs machine-readable JSON / CSV / Markdown. Un set `_WARNED_ALIASES` per-process garantit qu'un watch-mode session ne spam pas le log. Tests pin la sémantique one-shot.

C'est le **bridge** vers le retrait alias v0.9.0 décrit dans `SECURITY.md` (contrat back-compat).

### Linter locale

[scripts/lint_locales.py](../scripts/lint_locales.py) — outil dev, pas shipped au runtime. Catch les classes de drift exposées par les passes audit 7 + 8 :

- **Parité strict clés EN/FR** — chaque leaf key en en.json apparaît en fr.json et vice-versa.
- **Parité set placeholders** — chaque `{name}` en EN match le même set en FR. Protège `str.format(**kwargs)` des crashes KeyError.
- **Contrat trailing-whitespace** pour les `cli.error.*_prefix` keys (invariant I-2 pass 7).
- **Sanité length** — valeurs vides + > 1500 chars flagged. Threshold tuned pour pas false-positive sur les paragraphes techniques verbeux légitimes des `explain.*.{why,how}`.

[tests/test_v082_items.py::TestLocaleLinterSmoke](../tests/test_v082_items.py) shell vers le script donc un drift casse CI même sans run direct.

### Items déférés v0.9.0

- **D-1 / D-2 / D-4** de `project_v08x_deferred` — renumber sections + fusion `_ALL_SECTIONS`/`_ALWAYS_ON_SECTIONS` + sub-checks granulaires (BREAKING — affectent syntaxe scripts `bob --check=ssh,firewall`).
- **Retrait trap door `BOB_SANDBOX_LEGACY=1`** — BREAKING pour users avec env var set.
- **Parallel check execution** — `concurrent.futures` sur sections I/O-bound, touche threading invariants.
- **`--diff <baseline.json>`** — cross-machine baseline diff, additif, déféré pour bundler avec migration support de D-4.
- **Tutorial / getting-started guide** — substantial doc work.

### Numbers

- **6244 tests** (6198 → 6244, +46 net). 0 régression.
- 46 tests dédiés v0.8.2 sur 2 files : `test_v082_bash_completion.py` (21) + `test_v082_items.py` (25).
- 88 nouvelles locale entries (44 sections × 2 langues) + 8 `cli.test_webhook.*` keys.
- 1941 EN + 1941 FR locale keys total, 0 drift.

### Upgrade

`pipx upgrade bodyguard-of-bits`.

Gains user-facing :
- `bob --check=list` désormais self-documenting (44 descriptions sections)
- `bob --test-webhook` fonctionne (smoke sans audit complet)
- Bash completion de `--unignore` + `--ignore` + `--explain` keys suggère les EXPLAIN_KEYS canoniques
- Usage `EXPLAIN_KEY_ALIASES` surface un warning de déprécation pointant vers timeline retrait v0.9.0

**v0.7.x reste EOL** (déclaration formelle dans [SECURITY_FR.md](../SECURITY_FR.md) depuis v0.8.1). **v0.6.x reste EOL** (déclaré v0.7.2).

---

## [v0.8.1] — 05-06-2026

**Maintenance mineure + cycle audit deep-hardening.**

Ferme **26 tiers de gaps** sur 3 passes d'audit sub-agent (6/7/8) + un sweep initial drift / framing / silent-feature-gap. 5521 → **6198 tests**, +677 net, 0 régression. ~190 tests dédiés v0.8.1.

### Cycle initial (12 tiers)

#### T6 — audit couverture sévérité profiles

`bob/data/profiles/desktop.conf` +24 overrides → 36 au total ; `workstation.conf` +28 overrides → 31 distincts de desktop. Couverture ~30% des 107 actionable warn/alert keys. Domaines couverts : clamav (5 keys), rootkit.db_outdated, auditd.* (3), secure_boot.*, file_integrity.*, log_rotation.*, backup.no_backup, mac_policy.apparmor_no_enforce, password_policy.weak_minlen, firewall_stack.ip_forward_enabled, services.exposure.open_local, ssh.* secondaires.

#### T10 — i18n exceptions webhook + config + __main__

14 nouvelles locale keys EN+FR sous `webhook.error.*` × 6 / `config.error.*` × 4 / `cli.error.*` × 4. Pattern fallback dict miroir v0.7.2 M-4 : `_FALLBACK_LABELS` + `_fallback_t` dans chaque module ; signatures `send_webhook(..., t=None)` etc. acceptent un t optionnel. Pre-fix : 9 exception messages EN hardcoded, users FR voyaient mixed-language.

#### Retrait alias workstation (BREAKING)

`bob/profiles.py:123-124` — l'alias v0.1.0 qui silencieusement redirigeait `bob -p workstation` vers `desktop` est retiré. workstation.conf est maintenant un profile **first-class**. **BREAKING** : users sur l'alias voient sévérités différentes pour `backup.no_backup` / `auditd.*` / `mac_policy.apparmor_no_enforce` (restent à WARN sur workstation, INFO sur desktop).

**Migration** : copier `desktop.conf` vers `~/.config/bob/profiles/workstation.conf` pour restaurer la sémantique v0.8.0.

#### T11 — parité field Finding.detail (CSV + JSON v1/v2)

`bob/csv_output.py:25-44` column `detail` insérée entre `message` et `fix_cmd`. `bob/json_output.py:240-251 + 448-460` field `detail` dans finding dict v1 + v2. Additif, pas de schema break.

#### T26 — dispatch explain services.exposed.<id>

`bob/explain.py:433-510` nouveau `_render_dynamic_service_explain()` route lookup via `ServiceRegistry.get(svc_id)` + `service_risk.<subkey>.{level,exposure,threat}`. 38 services auto-explainables. Live UX : `bob --explain services.exposed.ssh` produit contenu CRITICAL/EXPOSURE/THREAT du SSH Server.

#### T27 — payload webhook detail + note parity

Generic payload embarque `detail` + `note` per finding ; Slack inline concatène le `detail` après ` — ` séparateur. Ferme format-parity pattern.

#### T31/T37 — nature backfill 90 sites

90 sites `warn/alert(_with_deduction)` sans `nature=` classifiés : 69 action + 59 improvement + 1 structural. Pre-fix `bob/fixes.py:32-34` filtre `nature == "action"` donc 88% des findings actionnables étaient silencieusement skipped par `--fix --apply`. Post-fix 100%.

Edge case ssh/_directives.py refactoré pour propager nature via kwargs dict explicit. 5 reverts pour aligner avec tests existants : risky_fs/risky_net (improvement), ntp.not_synchronized/not_enabled (improvement), smtp.exposed (improvement), rules.duplicate_found (action), rules.ipv6_missing (improvement).

#### T32 — validation typo profiles

`_recognised_override_keys` build catalogue (lru_cache(maxsize=1)) : EXPLAIN_KEYS ∪ `services.exposed.<id>` ∪ literal `key="..."` harvest. À la load, `[overrides]` keys absentes émettent `logger.warning(...)`. Compat-preserving.

**Self-catch notable** : T32 a chopé `ssh.x11_use_localhost` que J'AI moi-même ajouté en T6 — orphan dans desktop+workstation. Le mécanisme fait son boulot sur mes propres erreurs.

#### T39 — orphan service_risk.ollama_llm_server cleanup

Block locale retiré. Service Ollama réel a subkey `ollama_local_llm` (entry valide depuis v0.8.0 T2).

#### T57 — CLI --unignore

`bob/ignore.py:127-184` nouveau `remove_ignore_key()`. Wire CLI + 2 locale keys + mutual-exclusion guard avec `--ignore` (ajouté pass 6 M-4).

#### T60 — helper _t_or_hardcoded

`bob/__main__.py:67-83` returne `t(key)` si i18n initialisé, sinon `fallback`. Wire 3 sites pre/post-init (parse_args CLIError, main() catch-all). Pre-T60 : `Fatal error: …` + `Set BOB_DEBUG=1...` hardcoded EN même en audit FR.

#### T74 — redaction credentials URL webhook

`bob/webhook.py:60-66` regex ancré sur `://` boundary + `redact_url_credentials(url)` public helper. Wire `send_webhook` WebhookError sites + `__main__.py:386` success print. Original URL reste pour POST réel ; seul l'affichage opérateur est sanitisé.

### Audit pass 6 (5 findings shipped)

#### I-1 — preservation comments ignore.yml

`remove_ignore_key` re-écrivait en canonical form, détruisait silencieusement commentaires opérateur (`# Per ticket SECOPS-1234`).

Fix : line-walk in-place. Drop seulement `- key: <removed>`, préserve reste verbatim.

#### M-1 — T32 regex digits + file_perms.*

Regex `[a-z_]+` rejetait segments avec chiffres → `fail2ban.ssh_jail_active`, `ipv6.*` déclenchaient spurious warnings. Fix : `[a-z][a-z0-9_]*` + `file_perms.*` permissive prefix.

#### M-2 — services.exposure canonical set

Pre-fix registrait `services.exposure.{svc.id}` (bogus — runtime émet `services.exposure.{exposure_value}`). Fix : retrait + ajout canonical set de 7 base values × 2 (avec `_ufw_inactive` — narrowed pass 8 M-2 plus tard).

#### M-3 — service_label_to_subkey consolidation

T26 docstring claimait "single source of truth" mais display.py avait 2 copies inline. Fix : extract vers `bob/registry.py:60-92`, les 3 sites délèguent via import.

#### M-4 — --unignore docs + mutual-exclusion

Man page entry + CLIError guard.

### Audit pass 7 (3 findings shipped)

#### I-1 — remove_ignore_key regex match loader grammar

`startswith("- key:")` (un espace) ≠ loader regex (`\s+`). Files yamllint-style avec 2 spaces silencieusement un-removable → misleading "Key not present".

Fix : nouveau sibling regex `_KEY_LINE_MATCH_RE` (sans `\s*$` anchor). Cf. pass 8 I-1 pour unification définitive.

#### I-2 — FR colon typography drift

T10 + T60 ont laissé `:` ASCII hardcodé après `t()`. Convention FR = ` : `. Plus `cli.error.webhook_failed_prefix` contenait déjà ` : ` dans valeur FR → double-colon mixed style.

Fix : colon-space embarqué dans valeurs locale (EN `"Error: "`, FR `"Erreur : "`). 4 sites print drop le `: ` hardcodé. Drift introduit par mon propre T10.

#### M-1 — --show-ignored man description

Man page claimait "list keys and exit", code fait l'opposé (display inline pendant audit). Fix : réécriture du paragraphe.

### Audit pass 8 (5 findings shipped)

#### I-1 — _KEY_LINE_RE unification

Le pass 7 sibling regex pour inline comments était unreachable (defensive guard `load_ignore_keys` short-circuit avant). Méta-régression dans mon fix pass 7.

Fix : drop `\s*$` anchor de `_KEY_LINE_RE` itself, retirer `_KEY_LINE_MATCH_RE`. Loader + remover share single relaxed regex.

#### I-2 — runner.py 3 Warning sites un-i18n'd

T10 a loupé `runner.py:143,157,161`. Fix : `cli.error.warning_prefix` (FR `"Avertissement : "`) + namespace `cli.runner.*` (6 nouvelles keys × 2 langues).

#### M-1 — --webhook-secret phantom

`bob/cli.py:193` listait `--webhook-secret` dans `_VALUE_TAKING_OPTS` mais aucun handler n'existait. Errors inconsistents entre `--opt val` et `--opt=val`. Fix : retrait 1-line.

#### M-2 — _ufw_inactive narrowed

Mon M-2 pass 6 registrait `_ufw_inactive` pour les 7 exposures, runtime n'émet QUE pour `(no_rule, loopback_no_rule)`. Méta-régression dans mon fix pass 6. Fix : narrow.

#### M-3 — t() trailing whitespace contract

8 tests parametrized pin que `t()` ne strip pas trailing whitespace sur les 4 `cli.error.*_prefix` keys × {EN, FR}. Defends I-2 pass 7.

### Plus — autouse fixture i18n init

`tests/conftest.py` `_ensure_i18n_initialised_for_tests` mirror production invariant. Opt-out pour `test_i18n.py` (qui exerce bracketed-fallback contract).

### Numbers

- **6198 tests** (5521 → 6198, +677 net). 0 régression.
- ~190 tests dédiés v0.8.1 sur 8 fichiers
- 26 tiers de gaps fermés sur 3 cycles d'audit
- 22 nouvelles locale keys EN+FR
- 38 services explainable via T26 dispatch
- 90 sites nature backfill T31

### Upgrade

`pipx upgrade bodyguard-of-bits`.

Shifts comportementaux user-facing :
- **Profile workstation distinct de desktop** (BREAKING)
- **4 findings peuvent maintenant déduire des points** (T3 v0.8.0 + T31 v0.8.1) — score peut baisser 1-3pts
- **`bob --fix --apply`** couvre 100% des actionable findings (était 12%)
- **`bob --explain services.exposed.<svc>`** produit du contenu pour 38 services
- **`bob --unignore=KEY`** existe (CLI symmetry avec `--ignore`)
- **Webhook URLs credentials** affichées redacted
- **FR audits cohérents** sur typographie colon
- **Profile typos** émettent `logger.warning`
- **`--show-ignored`** correctement documenté

**v0.7.x est désormais en fin de vie depuis le 05-06-2026** — déclaration formelle dans [SECURITY_FR.md](../SECURITY_FR.md), miroir du pattern qui a retiré v0.6.x en v0.7.2. Aucun correctif de sécurité ne sera backporté en v0.7.x ; les utilisateurs doivent `pipx upgrade bodyguard-of-bits` vers v0.8.x pour les patchs sécurité. La ligne v0.8.x est largement rétro-compatible avec v0.7.x via les re-exports `__init__.py` + `--json-v1` pour les consumers JSON legacy, sauf pour le shift BREAKING workstation décrit ci-dessus (copier `desktop.conf` vers `~/.config/bob/profiles/workstation.conf` pour restaurer la sémantique v0.7.x sur ce profil).

v0.6.x reste EOL (déclaré en v0.7.2).

---

## [v0.8.0] — 04-06-2026

**Mineure majeure — drift batch + actions framing + audit silent-feature-gap.**

Clôture le cycle v0.7.x (4 patches hardening v0.7.1 → v0.7.4) et ouvre v0.8.x. Trois axes de travail dans le même bump : (1) un drift batch qui resynchronise toutes les surfaces doc/packaging désynchronisées depuis v0.6.2, (2) deux actions framing anti-sur-claim (encart "What BOB is / is NOT" + ligne d'hypothèses dans summary box), (3) un audit silent-feature-gap en 8 tiers qui ferme des gaps "feature documentée mais partiellement implémentée" identifiés post-v0.7.4.

### Drift batch (11 items — anti-désynchronisation)

Les 5 cycles patches v0.7.1 → v0.7.4 ont accumulé une drift doc/packaging silencieuse : 5 surfaces ont laissé fuir leur version. Le drift batch resynchronise tout en un seul commit + ajoute un 5e CI guard pour empêcher la récidive.

- **1. CHANGELOG FR backfill** — `CHANGELOG_FR.md` + `DOCUMENTS/CHANGELOG_FULL_FR.md` s'arrêtaient à v0.7.0b2. 5 entrées manquantes (v0.7.0 final + v0.7.1 + v0.7.2 + v0.7.3 + v0.7.4). Les lecteurs FR voyaient le projet "gelé" à une beta alors que PyPI shippait v0.7.4. Comblé via traduction des entrées EN équivalentes.
- **2. Man pages** — `man/bob.1`, `man/bob.conf.5`, `man/bob-profile.5` portaient `.TH BOB n "2026-05-29" "BOB 0.6.2"`. Bumpés à `"2026-06-04" "BOB 0.8.0"`.
- **3. Shields.io badges** — `DOCUMENTS/README_TECH.md` + `DOCUMENTS/README_TECH_FR.md` affichaient `version-v0.7.4-brightgreen` (à jour avec PyPI mais désync avec ce commit). Bumpés à `v0.8.0`.
- **4. `debian/changelog`** — toutes les entrées historiques étaient `UNRELEASED`. v0.8.0 ouvre avec `(0.8.0-1) UNRELEASED; urgency=medium` ; entrées antérieures préservées.
- **5. `packaging/rpm/bob.spec`** — `Version: 0.7.4` → `0.8.0` + nouvelle entrée `%changelog` v0.8.0-1 en tête.
- **6. `DOCUMENTS/TESTING.md`** — table per-version backfillée (v0.6.2 + v0.7.0 + v0.7.0b1-b4 + v0.7.1-4 étaient déjà ajoutés dans le drift batch ; v0.8.0 row ajouté).
- **7. `README.md` + `README_FR.md` Install section** — drift avec `README_TECH.md` : les README user-facing disaient juste `pipx install` + `sudo bob` sans expliquer le PATH restreint sudo. Synced sur le flow 4-substep de README_TECH.md (Prerequisites / Install / Enable sudo + bash completion / Uninstall) avec ton adapté (README = grand public, conservation du chemin absolu requis pour `sudo bob --install-completion`).
- **8. `tests/test_runner.py`** — smoke sur l'orchestrateur `_sec()` de `bob/runner.py` (le module à plus haute out-degree, 665L, sans test dédié). 3-5 smoke tests catch un drift Python 3.15+/16 en pytest local au lieu du cycle CI 30min.
- **9. 5e CI guard `tests/test_doc_version_consistency.py`** — `man/.TH × 3 + debian/changelog top + shields × 2 + rpm spec Version + CHANGELOG{,_FULL}{,_FR}.md top row` tous matchent `pyproject.toml::version`. Aurait caught les items 1-5 ci-dessus pre-tag-push. Pattern emprunté à `test_version_consistency.py` (leçon v0.7.0b2), scope élargi aux 7 surfaces.
- **10. Retrait orphan `bob/checks/__init__.py::__version__ = "1.14.0"`** — copy-paste v0.1.0 jamais consumé. Free cleanup, zero risk.
- **11. Documentation `BOB_DEBUG` dans `SECURITY.md`** — env var trap door (`bob/__main__.py:471`) précédemment non-documentée à côté de `BOB_SHARE` / `BOB_WEBHOOK_ALLOW_INSECURE` / `BOB_SANDBOX_LEGACY`.

### Actions framing (anti-sur-claim)

Critique externe ChatGPT 2026-06-02 sur un audit v0.7.4 : "pertinent comme outil de diagnostic technique mais pas fiable comme système de notation de sécurité absolue". Le diagnostic correct portait sur le **framing** (BOB ne dit pas assez fort qu'il audit sous hypothèses), pas sur le moteur. Deux actions Tier 1 shippées :

- **A1 — ligne footer `summary.context_disclaimer`** ([bob/display.py:581](../bob/display.py) + nouvelle clé locale `summary.context_disclaimer`) : `print_audit_summary` ajoute désormais une ligne `ℹ` supplémentaire juste après les notes existantes `summary.scope_line1` / `scope_line2` : *« Verdict conditionné par le profil et le contexte réseau ci-dessus. BOB est un auditeur de configuration hardening, pas un moteur d'analyse de menaces — à interpréter en conséquence. »* Le profil + contexte réseau sont déjà affichés dans la box du summary (lignes `Profil d'audit` + `Contexte réseau`), donc le disclaimer s'appuie dessus ; il ne re-émet PAS un en-tête templatisé `Hypothèses : profil=X | contexte=Y | posture=Z`. Pre-v0.8.0 la box affichait `Score 8/10 + FAIBLE` sans aucun rappel que ce verdict était *conditionné*. Un lecteur de capture d'écran pouvait conclure "tout va bien" sans voir le contexte. 1 print + 1 clé locale par langue. 0 schema change.
- **A2 — section "What BOB is / is NOT"** ([README.md](../README.md) + [README_FR.md](../README_FR.md) + [SECURITY.md](../SECURITY.md) + [SECURITY_FR.md](../SECURITY_FR.md)) : nouvel encart court (~15 lignes) qui clame explicitement que BOB **est** un auditeur de configuration hardening avec modulation contextuelle par profile + posture, et **n'est pas** : threat-modeling engine, scanner d'exposition réseau actif, system de verdict autonome. Le score reflète l'hygiène de configuration sous le profile choisi, pas la posture de sécurité absolue. Interprétation humaine requise pour traduire le verdict en "ma machine est-elle exploitable depuis Internet".

Coût combiné A1+A2 : ~75 lignes (~10 code + ~65 doc). Gain : pré-empte 80% des critiques type "BOB sur-claim". Rétro-compatible total.

### Audit silent feature-gap (8 tiers — gaps "documentée mais partiellement implémentée")

Sweep post-drift cherchant le pattern identifié par le Tier 1 (51 explain entries pour des findings WARN/ALERT documentés mais sans explain backfill). 8 tiers de gaps surfacés, 7 shippés en v0.8.0, 2 déférés à v0.8.1.

#### Tier 1 — Explain backfill (+51 entrées)

51 findings WARN/ALERT émis par le runtime avaient leur ligne `bob/locales/*.json` mais aucune entrée dans `bob/explain.py::EXPLAIN_KEYS` — donc `bob --explain <key>` renvoyait "No explanation available". Backfill complet via les 15 nouveaux préfixes : `backup, ddns, docker, fail2ban, firewall_stack, iptables_nft, log_rotation, logs, mac_policy, network_context, ntp, ports, rootkit, services, smtp`. Chaque entrée respecte le pattern canonique `<prefix>.<finding_id>` snake_case (pinné par `tests/test_explain_naming_convention.py`). Baseline EXPLAIN_KEYS : 117 clés / 30 préfixes (v0.7.0 baseline) → **168 clés / 45 préfixes** (v0.8.0 baseline).

#### Tier 1bis — SSH `_BadDirective.cmd_template` (+8 directives)

8 SSH directives `_BadDirective` listées dans `bob/checks/ssh/_directives.py::_BAD_DIRECTIVES` (PermitEmptyPasswords / X11Forwarding / IgnoreRhosts / HostbasedAuthentication / PermitUserEnvironment / StrictModes / AllowTcpForwarding / PubkeyAuthentication) émettaient leurs findings sans `cmd=`, donc `bob --fix --apply` dumpait "manual fix required" même quand la fix était une simple `sed -i 's/.../...\/g' /etc/ssh/sshd_config`. Dataclass `_BadDirective` gagne un field `cmd_template: str = ""` ; chaque directive ship maintenant son sed-line. `_apply_bad_directive` propage le template dans le finding kwargs.

#### Tier 2 — Services modernes (+6 entrées, 32 → 38)

`bob/data/services.json` listait 32 services depuis v0.5.x, principalement infrastructure historique (sshd, apache, nginx, mysql, etc.). 6 services modernes communs sur les hosts 2025+ n'avaient pas d'entrée de détection : **Tailscale** (mesh VPN WireGuard), **Caddy** (web server avec TLS auto), **AdGuard Home** (DNS ad-blocker), **Vaultwarden Password Manager** (Bitwarden-compatible self-hosted), **Ollama** (local LLM runtime), **Authelia** (auth portal SSO). 6 entrées schema complètes ajoutées (id+label+packages+services+ports+risk+config_key+detection avec binary / snap / config_files).

#### Tier 3 — `warn_with_deduction` backfill (4 findings)

4 findings émettaient un bare `result.warn(...)` (zéro impact scoring) alors qu'ils étaient documentés `nature="improvement"` (ergo méritaient une déduction de score). Backfill `warn_with_deduction` :

- `services.state.installed_inactive_critical` ([bob/checks/services.py](../bob/checks/services.py)) — service critique installé mais inactif (ex. fail2ban installé mais désactivé) : +1pt.
- `services.state.active_disabled` ([bob/checks/services.py](../bob/checks/services.py)) — service actif mais désactivé au boot (drift entre état courant et état persistant) : +1pt.
- `firewall.policy_unknown` ([bob/checks/firewall.py](../bob/checks/firewall.py)) — politique UFW indéterminée (parse failure ou état corrompu) : +2pts.
- `virt.snap_network` ([bob/checks/virtualization.py](../bob/checks/virtualization.py)) — snap virtualization tool avec exposition réseau (LXD/Docker via snap) : +1pt par occurrence, capped 2pts cumulative pour ne pas sur-pénaliser les hosts multi-snap-virt.

#### Tier 4 — `service_risk` locales backfill (5 services)

5 services avaient leur ID dans `bob/data/services.json` (donc détectés par le runtime) mais zéro couverture `service_risk.<id>.{level,exposure,threat}` dans `bob/locales/{en,fr}.json` — donc l'audit affichait `[risque indisponible]` dans le panorama services. Backfill EN+FR pour : **SMTP**, **NFS**, **Jenkins**, **OpenVPN**, **Squid**.

#### Tier 7 — Profile key rename (`hardening.auto_updates_missing` → `updates.unattended_not_configured`)

Les profils `bob/data/profiles/desktop.conf` + `workstation.conf` overridaient la sévérité de la clé `hardening.auto_updates_missing` — mais cette clé n'était plus jamais émise depuis v0.4.x (le runtime émet `updates.unattended_not_configured` à la place). Donc les users overridant la sévérité auto-updates sur desktop/workstation voyaient l'override silencieusement no-op. Rename des deux profils + mise à jour docstring `bob/profiles.py` + tests `tests/test_profiles.py` (18 occurrences renamed).

#### Tier 9 — Format parity Markdown + HTML (`Finding.detail` + `Finding.note`)

Les sinks `bob/markdown_output.py` + `bob/html_output.py` ignoraient les fields `Finding.detail` et `Finding.note` alors que terminal + JSON + text les surfaceaient. Donc un audit exporté en Markdown ou HTML perdait du contexte explicatif. Nouvelles clés locale `markdown_output.{note,detail}_label` + `html_output.{note,detail}_label` ; les deux sinks rendent maintenant ces fields uniformément. CSS HTML : nouveaux `.finding-detail` + `.finding-note` (font-size .82rem, color dim).

#### Tier 5 (false positive — no action)

Un scan initial avait flaggé 6 clés `_detail` apparemment orphelines, mais investigation a montré qu'elles étaient toutes consommées par des suffixes différents (ex. `<base>_enabled`, `<base>_profiles`). Aucune action.

#### Tier 6 → v0.8.1 (déféré)

Audit couverture sévérité profiles : 94% des findings utilisent la sévérité par défaut, ~20-30 clés sont candidates pour overrides profiles (ex. `ssh.password_auth` devrait être WARN en server profile mais OK en desktop). Listing à compléter avant remediation.

#### Tier 10 → v0.8.1 (déféré)

i18n 27 messages d'exception EN hardcoded dans `bob/webhook.py` + `bob/config.py` (ex. `raise ValueError("URL must start with http(s)://")`). Path d'erreur utilisateur en locale EN même en audit FR.

### Nouveaux test guards (4 fichiers)

Issus du drift batch (item 8 + 9) + de l'audit silent-feature-gap :

- **`tests/test_runner.py`** — smoke sur `bob/runner.py::_sec()` orchestrateur. Drift batch item 8.
- **`tests/test_explain_coverage.py`** — chaque clé actionable du runtime a son entrée `EXPLAIN_KEYS`. Aurait caught les 51 gaps T1.
- **`tests/test_fix_coverage.py`** — chaque finding actionable a soit `cmd=`, soit est dans la whitelist `_MANUAL_BY_DESIGN` avec rationale inline, soit est dans `_HELPER_DISPATCH_SITES` pour les clés non-littérales émises depuis helpers (ex. `weak_algo` helper émet 3 keys différentes ; `services` helper émet `services.exposed.<id>` dynamiques). 3 tests : whitelist sanity, helper-template présence, actionable coverage.
- **`tests/test_doc_version_consistency.py`** — drift batch item 9. 5e CI guard.

### Ce qui n'est PAS shippé

D-1..D-4 du contrat `project_v08x_deferred` (figé 2026-05-30 lors du kickoff Phase 2 v0.7.x) reste ouvert pour la continuation v0.8.x :
- **D-1** : renumber sections + uniformisation noms `emit_section()`
- **D-2** : fusion `_ALL_SECTIONS` + `_ALWAYS_ON_SECTIONS`
- **D-3** : retrait `EXPLAIN_KEY_ALIASES` obsolètes (cycle par cycle)
- **D-4** : sub-checks granulaires (ex. `ssh.x11_forwarding` → `ssh.x11.forwarding.server` + `.client`)

Retrait trap door `BOB_SANDBOX_LEGACY=1` (Phase 3 v0.7.0 deferred) également reporté à v0.8.x continuation.

### Numbers

- **~6008 tests** (5521 → ~6008, +487 net). 0 régression.
- 51 nouvelles entrées `EXPLAIN_KEYS` (Tier 1)
- 8 nouvelles `_BadDirective.cmd_template` (Tier 1bis)
- 6 nouveaux services `services.json` (Tier 2)
- 4 findings backfill `warn_with_deduction` (Tier 3)
- 5 services `service_risk.*` locale backfill (Tier 4)
- 4 nouveaux test guards (test_runner / test_explain_coverage / test_fix_coverage / test_doc_version_consistency)
- 2 actions framing (A1 ligne hypothèses + A2 section What BOB is/is NOT)
- ~1873 EN locale strings (~1827 baseline + 46 nouvelles)
- 174 références CIS (138 baseline + 36 nouvelles)

### Upgrade

`pipx upgrade bodyguard-of-bits`.

Shifts comportementaux user-facing :
- **Summary box** se termine maintenant par une note footer `Verdict conditionné par le profil et le contexte réseau ci-dessus. BOB est un auditeur de configuration hardening, pas un moteur d'analyse de menaces` sur chaque audit (A1) — pré-empte la mésinterprétation "BOB dit 10/10 = mon host est safe sur internet"
- **8 directives SSH** drop le footer "manual fix required" et shippent cmd= à la place (T1bis) — `bob --fix --apply` désormais actionable sur PermitEmptyPasswords / X11Forwarding / IgnoreRhosts / HostbasedAuthentication / PermitUserEnvironment / StrictModes / AllowTcpForwarding / PubkeyAuthentication
- **4 findings** qui étaient OK à 10/10 déduisent maintenant des points (T3) — score peut baisser de 1-3pts sur hosts avec services inactif+critique / services actif+disabled / firewall policy unknown / snap network virt
- **6 services modernes** (Tailscale/Caddy/AdGuard Home/Vaultwarden/Ollama/Authelia) gagnent détection + classification risque complète (T2) — hosts qui les exécutent voient leurs trouvailles surface dans le panorama services
- **Markdown + HTML** exports surfacent maintenant `Finding.detail` et `Finding.note` (T9) — rapports plus informatifs sans changement de schema
- **Profils desktop/workstation** : l'override sévérité `unattended_not_configured` fonctionne enfin (T7)

v0.6.x reste EOL (déclaré en v0.7.2).

---

## [v0.7.4] — 02-06-2026

**Quatrième patch hardening v0.7.x — deuxième passe deep-audit.**

Audit sub-agent deep sur le codebase v0.7.3 a fait surfacer 0 Critique + 6 Important + 8 Mineur findings. v0.7.4 ship les 14 (pattern bundle-aggressive, zéro défer ce cycle).

### Ce qui est fixé

#### Important

- **I-1 — fuites de sortie `--quiet`** : le block Docker `exposed_ports` ([bob/runner.py:467](../bob/runner.py)), `display_ports_overview`, `display_geoip_notice` et `display_log_results` printaient sur stdout même avec `-q`. `bob -q | cat` pouvait être non-vide quand geoip2 était indisponible, Docker exposait des ports, ou l'analyse logs surfaceait du contenu. Contract break. Chaque helper gate maintenant les print_* sur `config.quiet` ; `report.write_*` tournent toujours pour que le rapport `.log` reste affecté. `display_geoip_notice` reçoit un paramètre keyword-only `quiet: bool = False` (back-compat default).
- **I-2 — labels UI `--explain` i18n** ([bob/explain.py](../bob/explain.py) + nouvelle namespace locale `explain.ui.*`) : `WHY IT IS A RISK`, `HOW TO FIX`, `SCORING`, `Domain`, `Tool cap`, `Impact`, headers curses picker/detail, list-mode header `Available --explain keys:`, error path `No explanation available for: {requested}` / `Run 'sudo bob --explain list' …` — tous hardcoded EN sur audits FR. 18 nouvelles keys sous `explain.ui.*` dans les deux locales.
- **I-3 — flows CLI `__main__` i18n** ([bob/__main__.py](../bob/__main__.py) + nouvelles `cli.list.*` / `cli.ignore.*` / `cli.baseline.*` / `compare.no_baseline_yet` keys) : header `--check=list` + note prefix-matching + always-on header + bloc usage, validation invalid-key `--ignore=KEY` + canonical-hint + feedback success/already-present, `--reset-baseline` deleted/not-found/error, message `--diff` no-baseline-yet — tous hardcoded EN. Routés maintenant via `t()` avec le lang de l'audit.
- **I-4 — symétrie scheme webhook entre `webhook.py` et `config.py::set_webhook_url`** ([bob/config.py:261](../bob/config.py)) : v0.7.3 I-5 avait rendu `webhook.py::send_webhook` case-insensitive (`url.lower()`) ; la sister persistance `UserConfig.set_webhook_url` restait case-sensitive. Résultat : `bob --webhook HTTPS://...` envoyait OK au runtime puis silencieusement échouait à persist (`ValueError` swallowed par `__main__.py`, laissant config sauvegardée inchangée, donc next cron audit posté nowhere). Mirror le fix v0.7.3.
- **I-5 — duplicate private-IP matcher `bob/checks/services.py`** ([bob/checks/services.py:38](../bob/checks/services.py)) : l'unification architectural v0.5.6 de détection private-IP avait retiré une regex hand-rolled dans `bob/checks/logs.py` et documenté que `sysinfo._is_private_or_loopback_ipv4/_ipv6` est la single source of truth. Un duplicate `_PRIVATE_ADDR` regex était oublié dans `services.py::_classify_exposure`. v0.7.4 replace la regex par token extraction + délégation aux helpers sysinfo. Behaviour-preserved : tous tests existants 192.168 / 10.0 / 172.16 / 100.64 (CGNAT) / fc00:: (ULA) passent ; IPv6 zone-id (`fe80::1%eth0`) est strippé avant le helper call.
- **I-6 — CSV `risk` aligné JSON v1 (BREAKING)** ([bob/csv_output.py:55](../bob/csv_output.py)) : pre-v0.7.4 CSV `risk` utilisait `engine.effective_level.value` (posture-escalated) tandis que JSON v1 `risk` était restored à `engine.level.value` (score-only) par v0.7.1 I-3 pour préserver le contrat wire-format v0.6.x. Consumers comparant CSV + JSON v1 sur le même audit posture-escalated voyaient `risk` values différentes. v0.7.4 aligne CSV avec la sémantique score-only JSON v1 — **wire-format break** pour consumers CSV qui se reposaient sur la valeur escalated (migrer à `posture_escalation.score_level` JSON v2). User-decision : option A (rename + break) choisie explicitement per la stance contract-preservation v0.7.1.

#### Mineur

- **M-1 — `recurrence.py` dead `.tmp` cleanup retiré** ([bob/recurrence.py:67](../bob/recurrence.py)) : pre-v0.7.2 `_atomic.atomic_write` utilisait un suffix déterministe `name + ".tmp"` ; le handler tentait d'`unlink_missing_ok` ce path exact en cas de failure. Depuis v0.7.2 M-7 (`tempfile.mkstemp` random names), `recurrence.json.tmp` n'existe virtuellement jamais et le handler no-op silencieusement. `_atomic.atomic_write` clean déjà ses propres tmp leftovers via son block `except BaseException`. Ligne dead retirée.
- **M-2 — UX value-missing CLI** ([bob/cli.py:533](../bob/cli.py)) : pre-v0.7.4 `bob -l` (no value) tombait dans `Error: Unknown option: '-l'` — confusing, vu que `-l` EST connu et seule sa value est missing. Chaque value-taking elif était gated par `i + 1 < len(argv)` ; quand l'option était le dernier argv element, l'elif missait et le parser tombait dans le catch-all `Unknown option`. Nouveau `_VALUE_TAKING_OPTS` frozenset module-level énumère les value-taking flags ; le else-branch check `arg in _VALUE_TAKING_OPTS` et raise un `<flag> requires a value` plus clair. `-e/--explain` et `--watch` intentionnellement absents du set parce qu'ils ont no-arg forms documentées (interactive picker, default 30 s loop). Pins : 9 nouveaux tests.
- **M-3 — footgun trailing-colon `PYTHONPATH` wrapper cron** ([bob/cron/_io.py:45](../bob/cron/_io.py)) : pre-v0.7.4 le wrapper install-cron-generated exportait `PYTHONPATH=path:"$PYTHONPATH"`. Sous cron `$PYTHONPATH` est typiquement unset, donc la value resultante était `path:` — un trailing colon. Python interprète un trailing colon comme "search also CWD" (footgun long-standing) ; CWD root devient `/root`, donc un write à `/root/foo.py` shadowerait stdlib au prochain cron run. BOB ship le pitch hardening donc ce gap mattait. Fix via `path${PYTHONPATH:+:$PYTHONPATH}` — pas de trailing colon quand unset, sémantiquement identique quand set.
- **M-4 — `_sandbox.py` + `plugin_checks.py` WARN messages i18n + `key=`** ([bob/_sandbox.py:800](../bob/_sandbox.py) + [bob/plugin_checks.py:175](../bob/plugin_checks.py)) : 9 sandbox error WARN paths émettaient messages EN hardcoded ET pas de `key=`, donc `bob --ignore plugin.sandbox.timeout` n'avait pas de key à matcher (user n'avait aucun moyen de silencer les plugin failures répétées). Nouvelle namespace locale `plugin.sandbox.*` (9 keys). Chaque WARN porte maintenant `key="plugin.sandbox.<reason>"`. `t` threaded depuis `PluginCheck.run(t)` via `SandboxRunner.run(plugin_path, t)` → `_run_sandboxed(t)` / `_run_legacy(t)` ; absent `t` falls back EN via helper per-module `_sandbox_msg` / `_warn_msg` (back-compat avec callers legacy).
- **M-5 — labels banner `report.py::write_header` i18n** ([bob/report.py:219](../bob/report.py)) : le rapport `.log` `--detailed` commence avec EN hardcoded `[SYSTEM INFORMATION]` + `System` / `Host` / `Kernel` / `Firewall` / `User` / `Language` / `Port config`. Même Frenglish gap que v0.7.3 M-5 a fermé pour `write_summary`. `write_header` accepte maintenant un dict `labels=` optionnel ; `__main__.py` passe les values `t()` bound de l'audit depuis la namespace `banner.*` (3 keys réutilisées : `system` / `host` / `kernel` / `user` ; 4 nouvelles : `system_information` / `firewall` / `language` / `port_config`). Defaults préservent le wording EN pre-v0.7.4 pour back-compat. `MarkdownReport.write_header` accepte `labels=` pour Protocol parity mais l'ignore (rapports Markdown utilisent labels structurels fixes pour interop external-tool).
- **M-6 — parenthétique Frenglish `fixes.py`** ([bob/fixes.py:108](../bob/fixes.py)) : `print(f"  ✖ {t('fixes.manual')} (unsafe shell syntax in command)")` — `fixes.manual` était traduit, la parenthétique hardcoded EN. Nouvelle key `fixes.skipped_unsafe_shell` dans les deux locales.
- **M-7 — `json_output` utilise cache `engine.domain_scores`** ([bob/json_output.py:215](../bob/json_output.py) + [bob/json_output.py:418](../bob/json_output.py)) : les builders JSON v1 + v2 re-ranient `compute_domain_scores(engine)` pour assembler le block `domain_scores`, tandis que l'engine portait déjà les values cachées de `apply_domain_score_override`. Équivalent aujourd'hui ; future drift risk entre terminal display (lit cache) et JSON (recomputait) éliminée. Cache-first avec fresh-compute fallback pour engines sans override appliqué (défensif).
- **M-8 — `set_posture_from_engine` reject bool subclass-of-int** ([bob/scoring.py:706](../bob/scoring.py)) : `isinstance(True, int)` is True (bool subclass de int). Une entry `firewall: True` dans `domain_scores` slipperait past le branch `elif isinstance(int)` et forward `firewall_domain_score=True` à `set_posture`, qui raise alors TypeError depuis son guard explicit-bool. Le docstring du helper claim "centralise the dict-vs-int guard so a future contributor adding a new entry point can't accidentally pass the wrong shape" — ce fix v0.7.4 complète cette promesse. Bool normalisé à None maintenant (skip posture floor au lieu de crash).

### Ce qui n'est PAS shippé

Chaque candidat triagé shippé ce cycle. Pattern bundle-aggressive v0.7.3 appliqué sans exception (zéro défer, zéro v0.7.5 forced).

### Numbers

- **5521 tests** (5502 → 5521, +19 net). 0 régression.
- 1 pin parité CSV/JSON v1 risk (I-6)
- 1 pin symétrie scheme webhook (I-4)
- 4 pins display-quiet (I-1 `display_geoip_notice`)
- 9 pins UX value-missing CLI (M-2 incluant `--explain` / `--watch` no-arg sanity)
- 1 pin cron PYTHONPATH safe-form (M-3)
- 3 pins `set_posture_from_engine` bool/int/dict normalisation (M-8)

### Upgrade

`pipx upgrade bodyguard-of-bits`.

Shifts comportementaux user-facing :
- **Colonne CSV `risk` désormais score-derived** (BREAKING pour consumers CSV posture-aware — migrer à `posture_escalation.score_level` JSON v2 pour la valeur escalated)
- `--explain`, `--check=list`, `--ignore=KEY`, `--reset-baseline`, `--diff` no-baseline désormais full FR en locale FR
- `bob -l` (et autres value-taking flags) errent maintenant avec `requires a value` au lieu de `Unknown option`
- Webhook URL scheme matching case-insensitive sur persist aussi (pas seulement send)
- Wrappers cron regénérés via `sudo bob --install-cron` ne produisent plus de trailing-colon `PATH:`
- Header rapport `.log` `--detailed` en FR désormais full FR

v0.6.x reste EOL (déclaré en v0.7.2).

---

## [v0.7.3] — 02-06-2026

**Troisième patch hardening v0.7.x — full deep-audit pass.**

Audit sub-agent deep sur le codebase v0.7.2 a fait surfacer 0 Critique + 6 Important + 13 Mineur findings. Après cross-check de chaque finding dans le code, v0.7.3 ship 14 fixes (6I + 8M) et skip explicitement 5 mineurs avec rationale clair.

### Ce qui est fixé

#### Important

- **I-1 — locale FR "finding" → "découverte"** : v0.7.2 M-4 extraction avait laissé "finding" anglais dans 2 entries FR (`html_output.no_findings` / `findings_count`). Maintenant consistent avec le reste du codebase.
- **I-2 — `completion.py` SUDO_USER non validé** ([bob/completion.py:36-37](../bob/completion.py)) : `pwd.getpwnam(sudo_user)` raisait `KeyError` non géré sur value malformée/spoofée. Guardé maintenant via même regex pattern + `try/except KeyError` que `sysinfo.get_user_home`.
- **I-3 — colonne CSV `section` → `nature` (BREAKING)** ([bob/csv_output.py:26](../bob/csv_output.py)) : pre-v0.7.3 le CSV avait une colonne `section` qui portait en fait `Finding.nature`. Tests baked the mislabel. Consumers CSV externes parsant `section` recevaient nature strings. Header renommé pour matcher le contenu. CSV n'a pas de `schema_version` field donc wire-format break.
- **I-4 — `manage_logs.py` 3 `input()` bruts → `safe_input()`** ([bob/manage_logs.py:104, 365, 388](../bob/manage_logs.py)) : violait convention projet #2 (chaque prompt interactif via `bob._tty.safe_input`). Ligne 104 retient `input()` brut pour readline integration ; 365/388 sans excuse.
- **I-5 — scheme URL webhook case-insensitive** ([bob/webhook.py:206](../bob/webhook.py)) : `HTTPS://example.com` rejeté à tort. RFC 3986 permet toute casse ; normalisé via `url.lower()` pour le scheme check.
- **I-6 — convergence guard level markdown/html** ([bob/markdown_output.py:131-138](../bob/markdown_output.py)) : les 2 extractions M-4 v0.7.2 utilisaient idiomes différents pour le fallback `effective_level`. Convergé sur l'idiom html plus sûr.

#### Mineur

- **M-2 — forme `--lang VALUE` espace-séparée acceptée** ([bob/cli.py:236-243](../bob/cli.py)) : pre-v0.7.3 seul `--lang=VALUE` accepté ; autres options value-taking supportaient les 2 formes.
- **M-3 — `bob -e ""` empty key rejeté** ([bob/cli.py:308-313](../bob/cli.py)) : pre-v0.7.3 arg vide silencieusement consommé.
- **M-4 — argv hardening sur `-w` / `--ignore` / `--output-dir`** ([bob/cli.py](../bob/cli.py)) : le check space-form exige maintenant que next arg ne commence pas par `-`, donc typos comme `bob -w --quiet` errent au parse-time au lieu de silencieusement setter `webhook_url="--quiet"`.
- **M-5 — labels champs `report.py` i18n** ([bob/report.py:333-360](../bob/report.py)) : 6 labels EN hardcoded ("OK", "Warning", "Alert", "Score", "Risk", "Context") dans rapport `.txt` on-disk maintenant traduits via dict `labels=`. Nouvelles keys sous `report.field_*` + `report.summary_title` en `en.json` + `fr.json`.
- **M-6 — fix double-escape URL chars `_inline_format`** ([bob/report_markdown.py:469-481](../bob/report_markdown.py)) : URLs contenant `&` `<` `>` `"` double-escapées (parent `html.escape` + `_safe_url`'s `html.escape(quote=True)`), produisant `&amp;amp;` dans `href="..."`. Fixé via `html.unescape(m.group(2))` avant `_safe_url`. Latent (pas de BOB-emitted Markdown trigger ça aujourd'hui) mais réel.
- **M-10 — extract helper `set_posture_from_engine`** ([bob/scoring.py:683-720](../bob/scoring.py)) : setup posture-escalation dupliqué dans `bob/__main__.py` (audit summary) et `bob/watch.py` (boucle watch) consolidé en un seul helper. Ajoute aussi le guard dict-vs-int sur `domain_scores["firewall"]` (leçon Phase 1 4ed2e3b).
- **M-11 — `send_html_email` CRLF stripping défensif** ([bob/report_markdown.py:565-578](../bob/report_markdown.py)) : `\r\n` strippés des headers `recipient`, `subject`, `from_email`. Défense en profondeur contre callers tainted futurs ; callers actuels internes BOB.
- **M-12 — label risk html_output traduit** ([bob/html_output.py:140-152](../bob/html_output.py)) : pre-v0.7.3 le badge risk du summary header affichait `LOW`/`HIGH` quel que soit le locale. Maintenant les 2 surfaces utilisent le même contrat i18n. Nouvelles keys `html_output.risk_low/medium/high/critical` en `en.json` + `fr.json` (FR : `FAIBLE`/`MOYEN`/`ÉLEVÉ`/`CRITIQUE`).

### Skippés per `feedback-conservative-refactor` (5)

- M-1 f-string sans interpolation (registry.py)
- M-7 timestamp CSV sur every row (by-design self-contained CSV)
- M-8 `formatter.py` zéro in-tree consumers (documented stub future-API)
- M-9 `_atomic.py` `BaseException` width (intentionnel — catches Ctrl+C pour tmp cleanup)
- M-13 EXPLAIN_KEYS list→frozenset (perf cosmétique)

### Numbers

5490 → **5502 tests** (+12 net) : 1 pin CSV rename, 3 pins case-insensitivity webhook scheme, 6 pins CLI argv hardening, 2 pins traduction HTML risk-level. 0 régression.

### Upgrade

`pipx upgrade bodyguard-of-bits`.

Seuls shifts comportementaux user-facing : rename colonne CSV (consumers externes doivent update), rapports audit `.txt` FR ont désormais labels champs FR (plus de mixed-language), rapports HTML ont badges risque FR en locale FR. Webhook URL scheme matching case-insensitive.

---

## [v0.7.2] — 01-06-2026

**Deuxième patch hardening v0.7.x — clôture les 6 mineurs déférés par v0.7.1 + formalise EOL v0.6.x.**

### Ce qui est fixé

- **M-4 extraction i18n sur exports Markdown / HTML** — `bob/markdown_output.py` + `bob/html_output.py` routent maintenant chaque string user-facing via fonction `t(key, **kwargs)` optionnelle ; quand `t=None` (callers legacy / tests), un dict fallback EN `_FALLBACK_LABELS` dans chaque module fournit les strings v0.7.1 unchanged. Callers `__main__.py` passent le `t` + `lang` bound de l'audit pour que les exports héritent du locale opérateur. Nouvelles entries locale : 24 keys sous `markdown_output.*` + 22 keys sous `html_output.*` dans `en.json` + `fr.json`.
- **M-6 sysinfo accepte IPv6 public IP** — `bob/sysinfo.py:199` regex `^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$` remplacée par validation `ipaddress.ip_address()` ; hosts v6-only reportent maintenant leur adresse publique réelle au lieu de string vide.
- **M-7 collision tmp-file `_atomic.py` sous writers concurrents** — `tmp = path.with_suffix(path.suffix + ".tmp")` remplacé par `tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))`. Deux invocations `bob` concurrentes (cron + manuel + watch loop coïncident) ne racent plus sur le même tmp path.
- **M-8 `SCHEMA_*_KEYS` wirés comme invariants enforced** — `bob/json_output.py` exporte les frozensets `SCHEMA_V1_REQUIRED_KEYS` / `SCHEMA_V1_FULL_KEYS` / `SCHEMA_V2_REQUIRED_KEYS` / `SCHEMA_V2_FULL_KEYS`. Nouvelle classe test `TestSchemaConstantsPinActualOutput` assert chaque frozenset matche ce que le producer émet.
- **M-9 `--json-full --json-v1` help text** — `bob/cli.py:604` mentionne maintenant explicitement la combinaison.
- **M-10 paths détection posture `display.py` dédupés** — extrait `_compute_posture_annotation(engine, t) -> tuple` helper remplaçant le pattern dupliqué pendant le hotfix v0.7.0.
- **v0.6.x officiellement déclaré EOL dans `SECURITY.md` + `SECURITY_FR.md`** + GitHub Release v0.6.2 notes porte un banner EOL prominent.

### Numbers

5479 → **5490 tests** (+11 net) : 4 SCHEMA_*_KEYS pin tests (M-8), 3 pins routing i18n Markdown (M-4), 4 pins routing i18n HTML (M-4 + `lang` attr). 0 régression.

### Skippés

- M-11 (import Iterator cosmétique) NON shippé per `feedback-conservative-refactor` — skip-forever item.

### Upgrade

`pipx upgrade bodyguard-of-bits`. Webhook `BOB_WEBHOOK_ALLOW_INSECURE=1` (v0.7.1 I-5) reste la seule env var opt-in.

---

## [v0.7.1] — 01-06-2026

**Premier patch hardening v0.7.x — follow-up same-day à v0.7.0 final.**

Audit sub-agent deep sur le codebase v0.7.0 complet a surfacé 0C + 5I + 11M findings ; v0.7.1 ship 4 important + 3 minor (le reste déféré à v0.7.2).

### Ce qui est fixé

- **I-1 drift contrat watch-mode** — `bob --watch` créait un `ScoreEngine()` neuf par iteration mais n'appelait jamais `engine.set_posture(...)` et ne settait jamais `engine.ignore_keys = load_ignore_keys()`. Résultat : un host dont UFW vient de tomber continuait à afficher "risque FAIBLE" en watch mode alors que le prochain audit non-watch escalait correctement en HIGH. Fixé en propageant ignore list + règles posture v0.7.0 per iteration, et affichant `engine.effective_level.value` next to le score bar.
- **I-2 drift signature `MarkdownReport.write_summary`** — `display.print_audit_summary` (appelé uniquement sur `AuditReport` aujourd'hui) passe `posture_annotation=...` à `report.write_summary`. Le Protocol `Report` et l'impl `MarkdownReport.write_summary` n'acceptaient PAS le kwarg. Bug ne fire pas aujourd'hui mais c'est une mine. Fixé en ajoutant `posture_annotation: str = ""` aux deux.
- **I-3 break wire-format `risk` JSON v1** — v0.7.0 Phase 1 avait silencieusement shifté `risk` dans le schema v1 JSON de `engine.level.value` (score-derived) à `engine.effective_level.value` (posture-escalated). Cassait le contrat documenté "v1 layout matches v0.6.x EXACTLY". v0.7.1 revert le shift ; consumers v1 restent gelés à la sémantique v0.6.x. Consumers nécessitant la valeur escalated migrent à v2's `posture_escalation.score_level`.
- **I-5 URL webhook plaintext acceptée** — `send_webhook(url, ...)` acceptait `http://` et `https://`. Payload audit contient hostname + public_ip + score + alerts — leak posture audit en plaintext sur tout path réseau. v0.7.1 rejette `http://` par défaut ; opt out via nouvelle env var `BOB_WEBHOOK_ALLOW_INSECURE=1`.
- **M-1 import non utilisé** — `from typing import Any` dans `bob/plugin_checks.py` resté après le retrait T3 Step 3.
- **M-2 `_atomic.py` ne fsync pas** — docstring promettait persistance crash-safe mais l'impl skippait `fsync(fd)` avant close ET `fsync(dir_fd)` après rename. Fsync sur les 2 fds maintenant.
- **M-5 `--ignore=KEY` ne validait pas le pattern** — `add_ignore_key("anything goes here")` silencieusement accepté, writer YAML splittait sur whitespace et truncait au premier mot. v0.7.1 valide contre le pattern canonique EXPLAIN_KEYS AVANT le write ; bad keys retournent `EXIT_ERROR=3` avec hint.

### Numbers

5466 → 5479 tests (+13 net) : 5 pins ignore-validation, 1 atomic fsync spy, 2 pins webhook http rejection, 3 pins MarkdownReport signature parity, 2 pins watch-mode propagation. JSON contract test renamed + body inverted (`test_v1_risk_pins_score_only_level_not_effective_level`).

### Déféré à v0.7.2

I-4, M-4, M-6, M-7, M-8, M-9, M-10, M-11.

### Upgrade

`pipx upgrade bodyguard-of-bits`. Aucun changement contrat CLI ; consumers v1 JSON peuvent voir `risk` revert de posture-escalated à score-derived (intentionnel — c'est le fix I-3).

---

## [v0.7.0] — 01-06-2026

**Bump majeur — ouvre la branche stable v0.7.x.**

Roll-up du cycle beta b1+b2+b3+b4 (15+ commits) avec 3 phases thématiques et 4 garde-fous release-engineering ajoutés en vol.

### Phase 1 (Foundation T1)

Python 3.14 ajouté à la matrix CI ; nouvelle API `ScoreEngine.set_posture()` + property `effective_level` + block `posture_escalation` calculant `max(score_level, posture_floor)` ; nouvelle EXPLAIN key `risk.escalated_posture` ; box-score annote "(majoré par posture : X)" quand posture floor actif.

### Phase 2 (Schema v2 T2)

`build_json_data(..., schema_version="2")` est le nouveau défaut, flag `--json-v1` préserve le layout legacy v0.6.x. v2 fixe l'inconsistance type `network_context` (P1), renomme `timestamp`→`timestamp_utc`, ajoute `info_count` + block `posture_escalation` + `deductions_raw`/`open_ports_all` en mode complet + `domain_scores[d].deductions`. Nouveau fichier `tests/test_json_schema_v2.py`. **Baseline audit EXPLAIN_KEYS** = 117 keys / 30 préfixes / 100% conformance pinné par `tests/test_explain_naming_convention.py`.

### Phase 2.1 hotfix

Audit sub-agent pre-T3 a surfacé 5 important + 6 minors ; 5/5 important + 4/6 minors shippés. I-1+I-4 propagation `effective_level` aux 3 sinks ratés + champ `level_score_only` dans `history.jsonl`. I-2 extraction helper `bob.scoring.unpack_posture_escalation`. I-3 `set_posture` rejette bool explicitement avec TypeError clair. M-1 `--check=list` liste les 10 sections always-on. M-3 `report.write_summary` (.txt) surface annotation posture.

### Phase 3 (Plugin Sandbox Runner T3)

Nouveau `bob/_sandbox.py` (~900 LoC) implémente runner plugin restreint : isolation processus via `multiprocessing.get_context("spawn")`, timeout wall-clock 5s + `RLIMIT_AS=256MiB` + `RLIMIT_CPU=10s`, allowlist d'import, `__builtins__` restreints (`_ImmutableBuiltins`), wrapper `open()` rejetant write modes ET refusant reads sur `/etc/shadow` / `~/.ssh/id_*` / `/dev/mem` etc., méthodes write `pathlib.Path` monkey-patchées, strip extensif d'attributs `os` (84 attrs dangereux), CheckResult shippé via round-trip dict JSON-safe à travers la queue (pas de pickle d'objets plugin-contrôlés → pas de RCE parent via `__reduce__` malicieux). `BOB_SANDBOX_LEGACY=1` trap door déprécié avec log CRITICAL + write stderr per-run. Threat model recadré honnête dans `SECURITY.md` — **le sandboxing Python in-process N'EST PAS une frontière de sécurité** (consensus PEP 416) ; le sandbox catch les accidents + attaques naïves ; le profil AppArmor shippé est la vraie frontière.

### 4 guards release-engineering ajoutés en vol

(1) **integration-first** caught Phase 1 4ed2e3b crash dict-vs-int avant la première beta ; (2) **smoke-after-commit** caught classe discovery packaging v0.6.2 ; (3) **version-consistency** test caught drift `__version__` v0.7.0b1 dans b2 ; (4) **smoke-plugin-on-CI** ajouté après ship pattern v0.7.0b3.

### Numbers

5391 → **5466 tests** à travers le cycle v0.7.0, 0 régression. Sub-agent adversarial review pattern proven 2 fois (Phase 2.1 + T3 Step 4).

### Déféré à v0.8.0

D-1 sections renumber, D-2 fusion `_ALL_SECTIONS`+`_ALWAYS_ON_SECTIONS`, D-3 retrait aliases EXPLAIN_KEYS obsolètes, D-4 sub-checks granulaires, retrait trap door `BOB_SANDBOX_LEGACY=1`.

### Upgrade

`pipx upgrade bodyguard-of-bits`. Users avec plugins dans `~/.config/bob/checks.d/` ont le sandbox automatiquement ; users sans plugins voient la nouvelle posture escalation + sortie JSON schema v2. Branche v0.6.x officiellement EOL.

---

## [v0.7.0b4] — 01-06-2026

**Hotfix compatibilité CI pour v0.7.0b3.** Aucun changement threat-model ou behavior audit — mais le ship b3 utilisait `types.MappingProxyType` comme `__builtins__` restreints du sandbox, et CPython rejette les mappings non-dict comme builtins `exec()` sur toute version Python de la matrix CI SAUF 3.12.3 : chaque run plugin sur 3.10/3.11/3.13/3.14 raisait `SystemError`. Détecté par la matrix de test `publish.yml` immédiatement après le push tag b3. **Fix** : revert `_build_restricted_builtins` pour retourner le dict subclass `_ImmutableBuiltins` original shippé en b2. Bloque le path naturel-Python mais bypassable via `dict.__setitem__(bins, "eval", real_eval)` — même finding I-1 sub-agent que b3 tentait de fermer. Trade-off : I-1 unbound-bypass passe de "fermé" à "known limitation". Documenté + nouveau test pinning. **4e bug release-engineering sur la branche v0.7.x.** Nouveau guard pour v0.7.0 final : step smoke-CI loadant un plugin bénin sur chaque version Python matrix avant le tag. 5466 tests.

---

## [v0.7.0b3] — 31-05-2026

**Hardening sandbox + recadrage threat-model** suite à l'audit adversarial sub-agent T3 Phase 3 (3C + 5I + 7M).

### PoCs confirmés

- **C-1** : `from pathlib import os` smuggleait module `os` live au-delà de l'allowlist d'import ; strip list manquait `posix_spawn` / `open` / `write` / `chmod` / `unlink` / `environ` / `chdir`.
- **C-2** : RCE processus parent via pickle `mp.Queue` : plugin obtenait `eval` réel via `json.dumps.__globals__["__builtins__"]`, construisait classe avec `__reduce__` malicieux, attachait à `findings[0].template_vars`, le `q.get()` parent unpicklait et lançait `os.system` sous sudo.
- **Échappement architectural** : `real_import = json.dumps.__globals__["__builtins__"]["__import__"]` puis `real_import("subprocess")` — bypass tout hook en 5 lignes, consensus communauté Python depuis PEP 416 retiré (2012).

### Décision stratégique : Option B — défense en profondeur honnête + AppArmor real boundary

### Hardening shippé

- `_OS_DANGEROUS_ATTRS` étendu de 21 → 84 entries (closes C-1)
- `_serialize_check_result` / `_deserialize_check_result` round-trip dict JSON-safe à travers la queue (closes C-2)
- `_ImmutableBuiltins` dict subclass remplacée par `types.MappingProxyType` (closes I-1 — proxy read-only C-level)
- `q.close()` + `q.join_thread()` dans `try/finally` (I-2)
- deny-list read-path sur `open()` bloque `/etc/shadow` / `~/.ssh/id_*` / `/dev/mem` / `/proc/kcore` (I-5)
- `_apply_resource_limits` set `RLIMIT_CPU = 10s` en plus de `RLIMIT_AS = 256MiB` (M-4)
- warning `BOB_SANDBOX_LEGACY=1` via `logger.critical` + stderr write, re-émis per-run (M-6 + M-7)
- helper AST `bob._sandbox.has_run_check(source)` partagé (I-3)

### Numbers

5458 → 5465 tests, 0 régression. SECURITY.md réécrit avec threat model honnête : **"In-process Python sandboxing n'est pas une frontière de sécurité"**.

**Quiconque tourne des plugins de sources non confiance doit enforcer le profil AppArmor BOB** — code review reste mandatoire.

---

## [v0.7.0b2] — 31-05-2026

**Hotfix release-engineering pour v0.7.0b1.** Aucun changement de code, contrat JSON, EXPLAIN_KEYS, CLI ou comportement d'audit vs v0.7.0b1 — mais le wheel publié sous cette version reportait `BOB v0.6.2` dans toutes les sorties (bannière terminal, `--version`, champ `"version"` JSON, payload webhook, header du rapport).

### Ce qui a foiré

BOB déclare sa version à DEUX endroits :

  - `pyproject.toml` → drive la metadata du wheel (ce que PyPI lit, ce que `pipx` reporte comme version installée).
  - `bob/__init__.py::__version__` → drive le code runtime (ce que chaque sortie print via `from bob import __version__`).

Quand le commit ship v0.7.0b1 `a4b7b9b` a bumpé `pyproject.toml` de `0.6.2` → `0.7.0b1`, seul ce fichier a été mis à jour — `bob/__init__.py` est resté à `0.6.2`. Le wheel construit et uploadé sur PyPI s'identifie correctement comme `bodyguard-of-bits-0.7.0b1`, mais quiconque lance `pipx install --pre` et invoque le binaire voit `BOB v0.6.2` dans chaque surface qui lit `__version__`.

Détecté sur la VM Debian 13 de so6 pendant la validation beta v0.7.0b1 (31-05-2026) — la bannière disait `BOB v0.6.2` après un `pipx install bodyguard-of-bits-beta` clean du wheel `0.7.0b1`.

### Fix

  - `bob/__init__.py::__version__` bumpé à `"0.7.0b2"`.
  - `pyproject.toml` bumpé à `"0.7.0b2"`.
  - **Nouveau test invariant** `tests/test_version_consistency.py`
    (`test_init_version_matches_pyproject_version`) lit les deux valeurs
    et asserte l'égalité à chaque run CI + chaque pytest pre-ship local.
    Un drift futur entre les deux fichiers fait maintenant échouer la
    suite et surface le bug avant que tout tag soit poussé.

### Pourquoi c'est le 3ème bug release-engineering sur la branche v0.7.x

  1. **v0.6.2** — wheels manquaient `bob/checks/ssh/` et `bob/cron/` parce
     que `[tool.setuptools.packages.find].include` était une liste figée
     qui n'a pas été mise à jour quand v0.6.0 a introduit les splits.
  2. **Phase 1 4ed2e3b** — `engine.domain_scores["firewall"]` est un dict
     pas un int ; le dict a été passé par erreur à `set_posture()` et a
     crashé l'audit juste avant le summary box.
  3. **v0.7.0b1** — `__version__` pas synced avec pyproject.toml.

Chacun est une classe différente de failure (discovery packaging /
assumption contrat runtime / drift metadata version), et chacun a slippé
les suites unit + integration parce que le gap était à la frontière
entre le code Python et la chaîne d'outils release-engineering. La
stratégie de project_v07x_phase1 règle 1 (integration-first) catch la
classe assumption contrat runtime ; la règle 3 (smoke local après chaque
commit significant) catch la classe discovery packaging ; cette beta
release ajoute l'invariant version-consistency comme 3e guard
complémentaire.

### Ce que les testeurs doivent faire

Si tu as installé v0.7.0b1, upgrade vers v0.7.0b2 :

```bash
pipx upgrade --pip-args="--pre" bodyguard-of-bits-beta
sudo bob-beta --version   # doit print 0.7.0b2 (était 0.6.2 en b1)
```

Tous les autres testings v0.7.0b1 restent valides — le misreport était
UX-only, la logique d'audit, le scoring, la sortie JSON, l'escalation
posture, etc. étaient tous correctement du code v0.7.0.

---

## [v0.7.0b1] — 31-05-2026

**Première pre-release de v0.7.0** — opt-in via `pipx install --pip-args="--pre" bodyguard-of-bits`. Les utilisateurs stables (`pipx upgrade bodyguard-of-bits` sans `--pre`) restent sur v0.6.2 et NE sont PAS impactés par ce drop.

Bundle de **15 commits depuis v0.6.2** sur trois phases de travail sur la branche `v0.7.x` :

### Phase 1 — T1 Foundation refresh (6 commits, ~ +540 LoC, +35 tests)

  - **Python 3.14 ladder étape 1** (`1b581c0`) — ajout de 3.14 dans les matrices CI tests+publish + classifier. `requires-python` reste à `>=3.10` puisque upstream 3.10 EOL est 2026-10. Étape 2 (bannière deprecation `--help`) prévue prochain minor ; étape 3 (drop) pour release post-EOL.
  - **M-1 flag `time_simple` pour `parse_cron_file`** (`d972f17`) — `bob/cron/_parse.py` ne downgrade plus silencieusement à `hour=0/minute=0` quand minute/hour sont non-entiers (`*/15 * * * *`, `0 */6 * * *`). `CronEntry` gagne `time_simple: bool = True` ; le wizard de reschedule (dans `bob/cron/_manage.py` + `bob/tui/cron.py`) utilise `03:00` par défaut au lieu de `00:00` trompeur quand le schedule parsé n'est pas un HH:MM simple.
  - **M-7 `--check`/`--skip` reconnaissent les sections always-on** (`3865738`) — pré-fix, `bob --check=firewall` levait "matches no known section" parce que le validateur ignorait les 10 sections always-on (firewall, rules, ports_analysis, network_context, firewall_stack, ufw_logging, services, ddns, docker, virtualization). Nouveau tuple `_ALWAYS_ON_SECTIONS` dans `bob/runner.py` ; `--check=<always-on>` est maintenant input valide, `--skip=<always-on>` affiche un warning "has no effect" au lieu de swallow silencieusement l'intent utilisateur. Le wall-of-text "Available sections" dans les warnings de token inconnu est remplacé par une ligne pointant vers `bob --check=list`.
  - **Posture escalation** (`e3d998f`) — `ScoreEngine` gagne `set_posture()` + propriété `posture_escalation` + `effective_level` dérivé comme `max(level dérivé du score, plancher posture)`. Triggers (1er match wins) : `firewall_inactive` → `HIGH`, `iptables_input_accept` → `HIGH`, `firewall_domain_score ≤ 3` → `MEDIUM`. Expose ce que la Phase 1 fixe structurellement : un host UFW OFF avec score 8/10 affichait "risque FAIBLE" (score-only) — affiche maintenant "risque ÉLEVÉ" avec l'annotation parenthétique "majoré par posture : pare-feu inactif". Migration de 5 sites vers `effective_level` (bannière display, champ `risk` JSON v2, CSV, payload webhook, report.write_summary). Nouvelle clé EXPLAIN `risk.escalated_posture` (count 116 → 117). Nouvelles strings locales `scoring.posture.{firewall_inactive,iptables_input_accept,firewall_domain_low}` en EN + FR.
  - **Gestion pre-release tag par CI publish** (`9def225`) — `.github/workflows/publish.yml` détecte maintenant le suffix tag pre-release PEP 440 `(a|b|rc|.dev)[0-9]+$` et (a) synthétise des release notes minimales depuis `git log` quand aucune section CHANGELOG existe, (b) set `make_latest: false` + `prerelease: true` sur la GitHub Release pour qu'une pre-release NE override PAS le badge "Latest" de la ligne stable v0.6.x, (c) titre la release `"$VERSION (pre-release)"` quand aucun headline CHANGELOG trouvé. L'infrastructure rendant possible le ship v0.7.0b1 actuel.
  - **Hotfix crash posture** (`4ed2e3b`) — smoke test sur so6desktop a révélé que `engine.domain_scores["firewall"]` est un dict pas un int — le dict était passé par erreur à `set_posture(firewall_domain_score=...)` et crashait l'audit à la comparaison `<=` juste avant le summary box ("Fatal error: '<=' not supported between instances of 'dict' and 'int'"). Fixé en extrayant `["score"]` du dict + ajout d'un type guard à `set_posture` qui raise `TypeError` avec un message nommant explicitement l'erreur dict-vs-int. +5 tests (4 unitaires + 1 integration test qui build un vrai engine avec `apply_domain_score_override` et exerce le wire-up comme `__main__.py`).

### Phase 2 — T2 Schema v2 + audit EXPLAIN_KEYS (4 commits, ~ +940 LoC, +711 tests)

  - **Dispatch schema JSON v2 + flag `--json-v1` + block posture_escalation** (`e4420e2`) — `build_json_data()` gagne un paramètre `schema_version: str = "2"` avec type guard (`TypeError` pour non-str, `ValueError` pour valeurs non supportées). Deux producteurs privés `_build_v1` et `_build_v2` ne partagent aucun état pour la clarté. v2 fixe l'inconsistance de type `network_context` de v1 (P1 : même clé string en mode court mais overwritten en dict en mode complet), renomme `timestamp` → `timestamp_utc` (P/B-3), ajoute `info_count` top-level (B-7), expose le block `posture_escalation` `{applied, reason_key, score_level}` (P3/A-4), ajoute `deductions_raw` et `open_ports_all` en mode complet (B-4/B-5), et `domain_scores[d]` porte maintenant le count `deductions` (B-6). Nouveau flag CLI `--json-v1` (implique `--json`) retourne le layout legacy v0.6.x exactement pour les consommateurs qui n'ont pas migré. Drive 30 nouveaux tests intégration dans `tests/test_json_schema_v2.py` écrits avant l'impl per la règle integration-first.
  - **Pins gap baseline v1 + retraite B-2** (`54f3f14`) — 10 tests explicites dans `tests/test_json_schema.py::TestSchemaV1BaselineGaps` documentent les bizarreries v1 que la migration v2 adresse (P1 type swap, P2 shift sémantique risk, P3 posture_escalation absent, pas de marker UTC dans timestamp, pas de `info_count`, pas de `deductions_raw`, pas de `open_ports_all`, `domain_scores[d]` minimal). Un test garde contre la régression future en pinnant les noms *conservés* des champs `firewall_stack` bypass (`input_bypasses` / `forward_bypasses` — initialement scopés comme B-2 rename vers `*_count`, puis retirés pendant Step 1 de T2 quand l'écriture integration-first a révélé que les champs sont `list[str]` de descriptions de règles, pas des int counts — le nommage au pluriel était déjà correct).
  - **Pin convention de nommage canonique EXPLAIN_KEYS** (`f81dd46`) — audit des 117 clés explain + 30 préfixes a confirmé 100% conformance avec le pattern `<prefix>.<finding_id>` snake_case (exception unique : `file_perms.<path>.<finding_id>` gérée par `bob.explain.normalize_key`). Grep dans `bob/` a confirmé que chaque clé est référencée comme string literal (pas d'orphelines). Nouveau `tests/test_explain_naming_convention.py` (+710 assertions parametrized) pin : pattern canonique, identifiants lowercase, pas de double underscore, pas de tiret, pas de chiffre en début, vocabulaire de préfixes comme allowlist explicite `KNOWN_PREFIXES`, pas d'overlap entre clés explain et aliases, count audit = 117, count préfixes = 30. Ajouter un nouveau préfixe dans un futur commit fera échouer `test_key_prefix_is_known` jusqu'à ce que `KNOWN_PREFIXES` soit mis à jour, surfaçant l'ajout comme décision délibérée en code review. Zéro retrait en v0.7.0 — tous les candidats déférés à D-3 v0.8.0.
  - **Docs schema JSON v2 + v1 legacy + guide migration** (`eaea762`) — `DOCUMENTS/README_TECH.md` (et FR) gagnent une section comprehensive documentant les deux versions schema, la structure du block `posture_escalation`, chaque nouveau champ v2 avec type+description, le tableau des différences v1 vs v2 pour la migration, un snippet jq qui gère les deux versions, et la baseline d'audit EXPLAIN_KEYS (117 clés / 30 préfixes / pattern canonique). Ferme l'engagement public EXPLAIN_KEYS dans le docstring `bob/explain.py` avec enforcement opérationnel via tests.

### Phase 2.1 — Cleanup pre-T3 (4 commits, ~ +500 LoC, +18 tests)

Un audit profond sub-agent du diff cumulé Phase 1 + Phase 2 (per stratégie règle 6 project_v07x_phase1) a remonté 5 important + 6 mineurs ; 5/5 important + 4/6 mineurs shippés avant que T3 plugin sandbox runner ne démarre. Deux patterns récurrents ont conduit le cleanup : (a) la migration `effective_level` a été énumérée à la main et a manqué 3 sinks (HTML, Markdown, history.jsonl) qui leakaient tous l'ancien level score-only dans la sortie user-visible ; (b) le pattern type-guard défensif du hotfix Phase 1 n'était pas uniforme à travers les consommateurs d'engine.

  - **Propagation `effective_level` à HTML, Markdown, history.jsonl** (`ef7fb59`) — `bob/html_output.py:82` (`level_label`) et `bob/markdown_output.py:47` (`level_value`) utilisent maintenant l'`effective_level` avec un fallback `getattr` pour préserver les test mocks legacy. `bob/history.py::save_score` gagne un kwarg optionnel `level_score_only: str | None = None` ; quand fourni, écrit comme champ JSON séparé pour que l'analyse de tendance puisse reach soit la vue affichée (`level` = effective) soit la baseline score-only (`level_score_only` = non-escalé). `bob/__main__.py:359` mis à jour pour passer les deux : `save_score(engine.score, engine.effective_level.value, level_score_only=engine.level.value)`. +7 tests intégration utilisant un vrai `ScoreEngine` + `set_posture(firewall_inactive=True)` asserttant que le level rendu/persisté matche le contrat effective.
  - **Extraction helper `unpack_posture_escalation`** (`8167b76`) — nouveau `bob.scoring.unpack_posture_escalation(engine)` consolide le pattern défensif `getattr` + `try/except TypeError/ValueError` qui était dupliqué dans `display.py` et manquant dans `json_output.py::_build_v2`. L'unpack bare de `_build_v2` `_posture_floor, _posture_key = engine.posture_escalation` aurait crashé v2 JSON sur le même test MagicMock-style qui a déclenché le hotfix Phase 1 4ed2e3b pour la summary box. Le helper est la source unique de vérité : les output sinks de T3 plugin runner devraient le consommer directement. +5 tests couvrant engine clean, firewall-inactive, stubs legacy sans la propriété, valeurs de propriété non-itérables, et tuples sur-dimensionnés.
  - **Type guard posture + mineurs audit** (`8cdf545`) — bundle de quatre petits items audit : **I-3** `set_posture(firewall_domain_score=True)` était accepté (`isinstance(x, int)` retourne True pour bool) ; le guard rejette maintenant bool explicitement avec un message nommant la surprise. **I-5** `test_v2_posture_escalation_consistent_with_top_level_risk` avait `assert ... or True` rendant la branche `applied=True` passante de manière vacuous — réécrit pour asserter la forme explicite (`risk == "high"`, `score_level == "low"`, divergence). **M-4** alias mort `_SCHEMA_VERSION = DEFAULT_SCHEMA_VERSION` en bas de `json_output.py` retiré (zéro consommateurs via grep). **M-5** `test_v1_risk_is_one_of_canonical_values` ne vérifiait que l'enum membership — remplacé par `test_v1_risk_reflects_effective_level_not_score_only` qui build un vrai engine sans déductions + `firewall_inactive=True` et asserte que v1 émet `"high"`, pinnant le shift sémantique silencieux de la Phase 1 contre une revert accidentelle.
  - **Symétrie UI : `--check=list` + annotation posture report** (`a3294fd`) — **M-1** `bob/__main__.py:list_checks` affiche maintenant les 10 noms de sections always-on sous un second block (`Always-on sections (10 total — these always run, --skip has no effect on them)`) pour que le vocabulaire accepté par le validateur matche ce que `--check=list` documente dans l'aide. La ligne vague "Core checks (firewall, ports, services, logs) always run" est retirée puisque la liste explicite la remplace. **M-3** `bob/report.py::write_summary` gagne un kwarg optionnel `posture_annotation: str = ""` ; `bob/display.py` calcule l'annotation via le nouveau helper `unpack_posture_escalation` et la passe through pour que le rapport `.txt` on-disk reste synchronisé avec le summary box du terminal.

### Count tests + smoke validation

  - **5391 → 5409 tests** (+18 net Phase 2.1, +35 Phase 1, +711 Phase 2 — incluant l'audit parametrized EXPLAIN_KEYS), 0 régression à travers la chaîne de 15 commits.
  - **Smoke validé sur so6desktop** (Linux Mint 22.3, 31-05-2026) : `sudo bob -v -d --french` audite end-to-end, score 8/10, posture clean (UFW actif), `--json` émet schema v2 avec `posture_escalation: {applied: false}`, `--json --json-v1` émet le legacy schema_version="1" sans block posture_escalation, `--check=list` affiche les deux blocks sections + always-on, `history.jsonl` porte le nouveau champ `level_score_only`.

### Différé à v0.8.0 (contrat figé)

Per `project_v08x_deferred.md` :

  - **D-1** — sections renumber : uniformisation des noms `emit_section()` (44 sections, certaines incohérentes vs `_ALL_SECTIONS`). Reporté parce que le rename casse les scripts utilisant `--check=ssh,firewall`.
  - **D-2** — fusion `_ALL_SECTIONS` + `_ALWAYS_ON_SECTIONS` en un seul tuple avec flag `is_always_on`. Cosmétique ; dépend de D-1.
  - **D-3** — retrait `EXPLAIN_KEY_ALIASES` obsolètes — minimum 1 release notice par retrait alias.
  - **D-4** — sub-checks granulaires (ex. `ssh.x11_forwarding` split en server/client) — sur demande.

### Ce qui n'est PAS dans cette beta (encore)

  - **T3 — Plugin sandbox runner** (mode restricted pour `~/.config/bob/checks.d/*.py`) est la prochaine phase. Discussion design complétée (D + RestrictedPython pour sandbox, opt-out pour plugins, restrictions Tier 2, suite known-bad tests + review adversarial sub-agent). Le ship v0.7.0 final bundlera T3 plus le contenu de cette beta1.

### Appel à beta testers

C'est le premier drop user-facing de la ligne v0.7.x. Si tu peux :

```bash
# 1. Install la beta dans un venv pipx séparé pour garder ton stable v0.6.2 intact :
pipx install --pip-args="--pre" --suffix=-beta bodyguard-of-bits
# 2. Run un audit complet et regarde le nouveau block `posture_escalation` :
sudo bob-beta --json | jq .posture_escalation
# 3. Compare le comportement v2 vs v1 sur le même host :
sudo bob-beta --json          | jq '{schema_version, risk, timestamp_utc, network_context}'
sudo bob-beta --json --json-v1 | jq '{schema_version, risk, timestamp,    network_context}'
# 4. Reporte les anomalies via GitHub issues avec le tag beta.
```

La ligne stable v0.6.x n'est pas affectée. Le canal beta est purement opt-in via `--pre`.

---

## [v0.6.2] — 29-05-2026

**Hotfix packaging critique.** Tous les wheels shippés depuis v0.6.0 (v0.6.0 + v0.6.1) manquaient `bob/checks/ssh/` et `bob/cron/`. Voir `CHANGELOG_FR.md` pour le détail. Notes spécifiques à ce doc FULL :

### Pourquoi ce bug est intéressant

C'est un cas d'école du failure mode "tests passent, ship casse". Trois couches de tests avaient chacune une raison de ne pas le catcher :

1. **Tests unitaires** importent depuis le source tree. Le package `bob.checks.ssh` existe comme répertoire dans le working tree ; la résolution d'import Python le trouve via `sys.path` contenant le repo root. La config packaging discovery dans `pyproject.toml` est complètement bypassée.

2. **Smoke pre-ship `sudo python3 -m bob`** tournait depuis le working tree. Même résolution source-tree. Le smoke sur so6desktop reportait `BOB v0.6.1` et un audit normal — exactement parce qu'il chargeait le source directement, pas le wheel v0.6.1.

3. **CI `integration.yml`** utilisait `pip install -e .` (mode editable). Les editable installs ajoutent le repo root à `site-packages` via un fichier `.pth`. Ils bypassent DÉLIBÉRÉMENT la discovery `find_packages()` pour iteration rapide.

Le bug surface seulement quand : (a) un wheel est build, (b) installé là où le source tree N'est PAS sur `sys.path`, (c) l'installer import un module depuis un sous-package manquant.

C'est exactement le workflow pipx upgrade.

### Mécanique du fix

Changement d'1 ligne dans `pyproject.toml` :
```diff
-include = ["bob", "bob.checks", "bob.tui"]
+include = ["bob*"]
```

Le glob `bob*` matche tout package commençant par `bob`. C'est `bob`, `bob.checks`, `bob.checks.ssh`, `bob.cron`, `bob.tui`, et tout futur `bob.something`.

### Hardening CI

Deux changements complémentaires dans `.github/workflows/integration.yml` :

**(1)** `pip install -e .` → `pip install .` — chaque distro build et install un vrai wheel.

**(2)** Nouveau smoke step explicite qui import chaque module v0.6.x-ajouté. Tout futur contributeur qui ajoute un `bob/foo/` sous-package doit étendre cette liste.

### Validation cross-distro

Le nouveau smoke step CI a tourné sur les 7 distros (Debian 12/13, Ubuntu 22.04/24.04/25.04, Kali rolling, Fedora 41) pour le push v0.6.2 et passe partout. Confirme que le fix est correct et le garde opérationnel.

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4600 passed in ~6s
```

**4600 inchangés.** Le fix est dans `pyproject.toml` (config packaging) et workflow CI (opérationnel), pas dans le code.

### Path d'upgrade

```bash
pipx upgrade bodyguard-of-bits
bob --version  # doit afficher "bob 0.6.2"
sudo bob --help > /dev/null  # doit pas crash
```

### Leçons enregistrées

- **Editable installs cachent les bugs packaging.** Tous les CI integration utilisent `pip install .` désormais.
- **Glob > liste figée** pour `setuptools.packages.find.include` dans les projets qui peuvent splitter des modules.
- **Smoke import step pour chaque nouveau sous-package** : catch-all low-cost qui surface le bug class à CI time au lieu du runtime utilisateur.
- **Les audits scopes devraient inclure `pyproject.toml`** pour le packaging drift, pas seulement le code Python runtime.

---

## [v0.6.1] — 29-05-2026

**Première release hardening sur la branche v0.6.x.** Sub-agent d'audit profond a produit 14 findings (0 critique + 6 important + 8 mineur) ; 6 important + 4 mineur shippés. L'audit a révélé deux **contrats demi-appliqués** depuis v0.5.x — atomic-write (paths de mutation fixés en v0.5.7 #I-3 mais pas les paths de création) et gestion EOF (`manage_logs.py` fixé en v0.5.7 #I-2 mais pas les wizards cron ni `fixes.py`) — plus une **branche validator non-testée** dans le parser de step cron. Tous adressés.

Voir `CHANGELOG_FR.md` pour le détail par finding. Cette release introduit `bob/_atomic.py` (helper consolidé) et `bob/_tty.safe_input()`. Le pattern audit→fix→ship répété de v0.5.x continue.

### Pourquoi les splits + sunset v0.6.0 n'avaient pas surfacé ces bugs plus tôt

v0.6.0 était structurel (splits + suppression UFW_AUDIT_SHARE) — pas de nouvelle logique. La campagne v0.5.x focalisait sur un set de modules différent : `bob/checks/logs.py`, `bob/manage_logs.py`, `bob/tui/cron.py`, plus 22 modules core. Les paths d'install cron (`bob/cron/_install.py`, branche cron-install de `bob/tui/cron.py`) et `bob/ignore.py` étaient parmi les ~25 modules "spot-checked" plutôt que deep-audited — donc le contrat atomic-write demi-appliqué (mutation fixé en v0.5.7 #I-3, création non touché) et l'écriture non-atomique de `ignore.py` ont survécu.

L'audit v0.6.1 ciblait explicitement le drift post-v0.5.x + les modules que v0.5.x avait spot-checked. C'est de là que viennent les 6 findings important.

### Consolidation contrat atomic-write (cleanup high-leverage)

Avant v0.6.1, 5 modules implémentaient leur propre version "write tmp + os.replace" avec variations subtiles. 3 modules N'utilisaient PAS atomic write malgré la décision architecturale SNAPSHOT.md qui le réclamait. 1 module (`bob/history.py:58`) utilisait `Path.open("a")` qui hérite du umask process — privacy-sensitive vu le contenu.

v0.6.1 extrait `bob/_atomic.py::atomic_write(path, content, *, mode=)` source unique. Tous les sites existants migrés ; tous les sites manquants fixés. `bob/cron/_io.py::_atomic_write` gardé en alias une-ligne pour backwards-compat tests.

### Complétion contrat gestion EOF

v0.5.7 #I-2 annonçait "tous les sites de read interactif dans BOB routent EOF à empty-string". C'était vrai pour `bob/_tty.read_line` et `bob/manage_logs.py` (les 3 sites fixés en v0.5.7). C'était faux pour `bob/_tty.prompt_wizard` (aucune try), `bob/cron/_install.py` (5 sites), `bob/cron/_manage.py` (5 sites), `bob/fixes.py:103`.

v0.6.1 ajoute `safe_input(prompt) -> str` à `bob/_tty.py` (variante swallow-EOFError) et :
- Patche `prompt_wizard()` pour aussi catcher `EOFError → None`
- Migre les 11 sites `input()` brut vers `safe_input`

Différence sémantique intentionnelle : confirmations (`y/N`) veulent `""` = "non", wizards cancelables veulent `None` = "user abandonne".

### `_validate_cron_field` step bounds (I-3)

Vrai bug. Validator à `bob/cron/_parse.py:262` checkait `step_s.isdigit() and int(step_s) >= 1` — mais jamais borné `int(step_s)` contre le range du field. Pour minute (0-59), `*/200` validait avec succès ; cron interprétait "toutes les 200 minutes" = ne se déclenche jamais (roll-over horaire). Reproducer :
```python
>>> _validate_cron_field("*/200", "minute", 0, 59)
''  # pré-fix : vide = valide
```
Post-fix retourne `"minute step '200' exceeds field range (60)"`. Cas boundary `*/60` toujours accepté (= "minute 0 chaque heure").

### `shlex.quote()` sur paths `cmd=` (I-4)

Les strings de commande auto-fix interpolent des paths dans des commandes shell. Le path auto-apply (`bob/fixes.py`) utilise `shlex.split(cmd)` avant `subprocess.run([list])`, donc un path-with-spaces non-quoté est split en multiples tokens et chmod target le mauvais fichier.

8 sites fixés (SSH paths from `pwd.getpwnam(SUDO_USER).pw_dir`, file_perms scans, firmware pkg). 13 sites restants safe-by-construction.

### `history.jsonl` mode 0o600 (I-5)

Bug class subtile : `Path.open("a")` utilise le umask process pour le create-mode. Umask défaut `0o022` → `0o644` = world-readable. Cadence audit + timestamps score privacy-sensitive sur systèmes multi-user.

Le path de rotation à `bob/history.py:74` utilisait déjà `os.open(..., 0o600)`. Le first-write à ligne 58 non. Fix : `os.open(O_WRONLY | O_APPEND | O_CREAT, 0o600)` puis `os.fdopen(fd, "a")`. Mode 0o600 appliqué seulement à création ; mode fichier existant préservé.

### `ignore.py` atomic write (I-6)

Pré-fix, `bob/ignore.py:93` faisait `os.open(str(path), O_WRONLY | O_CREAT | O_TRUNC, 0o600)` direct sur la destination. Power-loss entre `O_TRUNC` et `write` laissait `ignore.yml` vide (corruption — perte de toutes les clés précédemment ignorées, sans path de recovery).

Migré à `atomic_write(path, content, mode=0o600)` via le helper v0.6.1.

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4600 passed in ~7s
```

**4583 → 4600 (+17).**

Nouveaux : `TestAtomicWritePublicAPI` (4), `TestCronLegacyAliasStillWorks` (1), `TestHistoryFileMode` (2), `TestIgnoreAtomic` (2), `TestSafeInput` (3), `TestStepBoundedToFieldRange` (5).

### Diff net

Voir CHANGELOG_FULL.md (en) pour le tableau détaillé. ~12 fichiers code + 2 fichiers test + standard 17 fichiers version/changelogs.

### Cumul campagne audit

| Release | Modules touchés | Findings shippés | Tests ajoutés |
|---|---|---|---|
| v0.5.5 | 22 deep + ~15 spot | 19 (4C + 4I + 11M) | +7 |
| v0.5.6 | logs.py (662L) | 10 (0C + 2I + 8M) | +15 |
| v0.5.7 | manage_logs.py + tui/cron.py (~1920L) | 6 shippés + 5 déférés | +11 |
| v0.5.8 | 5 mineurs v0.5.7-déférés | 5 (tous mineurs) | +12 |
| **v0.6.1** | **audit codebase-wide + modules post-split v0.6.0** | **6I + 4M (4M déférés)** | **+17** |

**Cumul** : ~85 findings hardening fermés sur 5 cycles audit. 0 finding critique en suspens. Deux contrats uniformément enforced (atomic-write + EOF handling). La recommandation "extraction helper atomic-write" des observations cross-cutting SNAPSHOT.md est maintenant actionnée.

### Et après

v0.6.x continuera à recevoir des releases hardening au fil des findings (typiquement via tests cross-distro ou reports contributeurs). Pas de nouvelle campagne audit planifiée — la passe v0.6.1 a fermé les gaps cross-cutting que la campagne v0.5.x avait laissés ouverts. Releases bug-fix futures seront targeted par-issue plutôt que wholesale audit-driven.

---

## [v0.6.0] — 25-05-2026

**Bump majeur ouvrant la branche v0.6.x.** Deux splits architecturaux (#13 + #14) délibérément déférés tout au long du cycle v0.5.x, plus un sunset honoré (env var legacy `UFW_AUDIT_SHARE`). Tous les changements contract-preserving via re-exports `__init__.py`.

Voir `CHANGELOG_FR.md` pour le détail par module. Notes spécifiques à ce doc FULL :

### Pourquoi deux splits de fichier dans une release majeure

Le principe conservative-refactor (cf. memory [[feedback_conservative_refactor]]) — "gain × risque ≤ 0 dans une release contract-preserving = STOP" — interdisait les splits pendant v0.5.x. Splitter un fichier 1000+ LoC requiert :
- Déplacer chaque fonction vers un nouveau module
- Ajuster tous les imports internes
- Ajuster tous les imports externes (autres packages + tests)
- Risquer des bugs subtils d'ordre d'import ou de cycle qui ne surfacent pas dans les unit tests

Dans une release patch v0.x.y, c'est high-risk pour un gain marginal de lisibilité. Dans un bump majeur v0.x+1.0, les imports sont ATTENDUS de bouger (c'est la convention pour les versions majeures de shipper des changements structurels), donc le risque est socialisé. v0.6.0 est le bon vecteur.

### Pourquoi re-exports via `__init__.py` plutôt que migration de path

Les splits auraient pu déplacer les symboles publics vers de nouveaux chemins d'import (ex. `from bob.checks.ssh.snapshot import SSHSnapshot`). Ce serait un vrai breaking change requérant un cycle de deprecation. À la place, chaque symbole public est re-exporté depuis le `__init__.py` du package, donc `from bob.checks.ssh import SSHSnapshot` continue à marcher identiquement.

Tradeoff : le fichier `__init__.py` du package devient une liste de re-exports (boilerplate ennuyeux), mais :
- Zéro breakage user-visible
- Fichiers tests inchangés
- Intégrations externes inchangées
- L'option de migrer les chemins d'import en v0.7+ reste ouverte si un redesign API plus profond est voulu

C'est le même pattern que la stdlib Python utilise pour beaucoup de ses packages (ex. `email.mime.text.MIMEText` est aussi re-exporté comme `email.MIMEText`).

### Break du cycle dans le package ssh

La dépendance naturelle est bidirectionnelle :
- `_parsers` retourne des instances des dataclasses définies dans `_snapshot` → besoin de les importer
- `_snapshot.SSHSnapshot.from_system` appelle des fonctions parser de `_parsers` → besoin de les importer

Pour break le cycle : `_parsers` importe les dataclasses depuis `_snapshot` au niveau module ; `_snapshot.from_system` utilise un import local de fonction `from . import _parsers`. C'est propre parce que :
- Les dataclasses load en premier (pas de dep sur `_parsers`)
- Les parsers load en second (utilise les dataclasses depuis `_snapshot` déjà-loadé)
- `from_system` ne résout `_parsers` qu'au call time, moment où tout est loadé

Le pattern est documenté dans les docstrings module de `_snapshot.py` et `_parsers.py` — les futurs contributors qui ont besoin d'ajouter un nouveau parser ou modifier `from_system` savent qu'il ne faut pas ajouter un import top-level qui ré-introduirait le cycle.

### Gotcha résolution path `build_script_content`

Pré-v0.6.0, `bob/cron.py` vivait à un niveau sous `bob/`, donc `Path(__file__).parent.parent` résolvait vers la racine du repo (PYTHONPATH-able). Post-split, `_io.py` vit DEUX niveaux sous `bob/` (`bob/cron/_io.py`), donc la fonction walk maintenant TROIS parents :

```python
bob_path = str(Path(__file__).parent.parent.parent)
#                       ^^^^^^^^^^^^^^^^^^^^^^^^^^^
#                       _io.py → cron/ → bob/ → racine repo
```

C'est le seul changement "subtil" en v0.6.0 — partout ailleurs, les splits sont pur déplacement de code. Le smoke test `tests/test_cron.py::TestDatetimeImportLifted::test_build_script_content_still_stamps_date` exerce la fonction end-to-end et aurait catché une régression.

### Updates infrastructure tests (3 fixes triviaux)

Trois fichiers tests ont eu besoin d'updates pour accommoder la nouvelle structure de package :

1. **`tests/test_template_vars_migration.py`** — `_check_modules()` / `_module_paths()` étendu pour recursivement scanner les répertoires de package. Liste pilote migrée des noms suffixés `.py` aux noms de module.
2. **`tests/test_domain_scores_mapping_complete.py`** — changement d'une seule ligne `glob` → `rglob` avec filtre `__pycache__` pour que l'AST scanner pickup `bob/checks/ssh/_subchecks.py`.
3. **`tests/test_cron.py::TestApplyCronScheduleAtomic`** — target patch shifté de `bob.cron._atomic_write` (re-export package) à `bob.cron._io._atomic_write` (où `apply_cron_schedule` appelle effectivement). Le patch doit être set sur le module où le call site lit, pas où la fonction se trouve aussi re-exportée.

Ce sont des updates mécaniques sans changement de scope. La couverture reste identique : 4583 tests, 0 ajouté, 0 retiré.

### Mécanique du retrait `UFW_AUDIT_SHARE`

La chaîne de deprecation (12+ mois) :

- **v0.4.2** (2026-05-14) : `BOB_SHARE` documenté comme le contrat ; `UFW_AUDIT_SHARE` accepté comme alias legacy avec notice `logger.info(...)`
- **v0.5.4** (2026-05-23) : `logger.info` upgradé à `logger.warning(...)` avec message explicite "DEPRECATED since v0.5.4, will be REMOVED in v0.6.0. Update your installer to BOB_SHARE..."
- **v0.6.0** (cette release) : constante `_ENV_LEGACY` supprimée, lecture fallback supprimée, branche warning supprimée. La variable est maintenant silencieusement ignorée — les packages settant encore verront `resolve_share_dir()` retourner None et fall back aux data package-local, ce qui est le default safe.

Changement net dans `bob/_paths.py` : -20 lignes (une constante, une lecture fallback, la branche warning). La docstring est mise à jour pour noter "removed in v0.6.0" pour référence historique. Deux références commentaire stales dans `bob/i18n.py:44` et `bob/registry.py:38` ont aussi été mises à jour.

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4583 passed in ~7s
```

**4583 inchangés.** Zéro changement de comportement.

### Diff net

| Fichier | Delta |
|---|---|
| `bob/checks/ssh.py` (supprimé) | −1296L |
| `bob/checks/ssh/` package (5 fichiers) | +1402L (+106 overhead depuis `__init__.py` + docstrings par fichier + imports module-level) |
| `bob/cron.py` (supprimé) | −1204L |
| `bob/cron/` package (5 fichiers) | +1359L (+155 overhead similaire) |
| `bob/_paths.py` (drop UFW_AUDIT_SHARE) | −20L |
| `bob/i18n.py`, `bob/registry.py` (cleanup docstring) | −2L |
| `tests/test_template_vars_migration.py` (support rglob) | +30L / −10L net |
| `tests/test_domain_scores_mapping_complete.py` (shift rglob) | +3L / −1L |
| `tests/test_cron.py::TestApplyCronScheduleAtomic` (target patch) | +2L / −0L |
| Bump version + changelogs | ~17 fichiers standard |

**Cumulé : ~+330 LoC overhead** pour le split (à travers les deux packages) vs l'équivalent monolithique. Justifié par le gain de modularité — le plus gros module simple post-split est 529L (bien sous le soft ceiling 1000-LoC du projet), down de 1296L pré-split.

### Observation cross-cutting : la surface API publique est maintenant explicite

Pré-v0.6.0, les monolithes v0.5.x exposaient ~30 symboles implicitement (tout top-level non-préfixé `_`). Avec le split package, la liste re-export `__init__.py` rend l'API publique explicite et reviewable :

- `bob/checks/ssh/__init__.py` : 7 noms re-exportés (`SSHSnapshot` + 5 dataclasses + `check_ssh`) + 6 helpers test-only
- `bob/cron/__init__.py` : 17 noms re-exportés (set compat full v0.5.x) + re-export `_EMAIL_RE` depuis `bob.config` + re-export `datetime` pour test v0.5.8

Les futurs contributors qui veulent ajouter un nouveau symbole public doivent explicitement opt-in en le listant dans `__all__` et/ou le bloc d'import. C'est un side-benefit utile du split qui n'était pas part de la motivation audit originale.

### Roadmap

v0.6.x accueillera :
- Maintenance + bug reports terrain cross-distro
- Possible unification prompt TUI (était candidate v0.6.0 mais punted pour maintenir le focus release sur les splits)
- Planning cadence schema JSON v2 (pas de breaking changes encore — plan documenté pour v1.0)
- Préparation EOL Python 3.10 (deviendra probablement candidate bump min-version en v0.7+)

Aucune campagne deep-audit prévue — la campagne v0.5.x s'est fermée exhaustivement. Tous les futurs audits seront triggered par des concerns spécifiques (une nouvelle classe de vulnérabilité, un CVE dans une dépendance, une requête de contributor) plutôt que des sweeps proactifs.

---

## [v0.5.8] — 25-05-2026

**Release cleanup.** Clear des 5 mineurs cosmétiques explicitement déférés par v0.5.7 (M-2, M-5, M-6, M-7, M-8). Tous les cinq sont des améliorations layout / lisibilité / nommage-explicite sans delta comportemental en opération normale. **Cela ferme la campagne deep-audit v0.5.x — branche intégralement auditée (25 modules deep + ~25 spot-checkés, 0 finding critique en suspens).**

Voir `CHANGELOG_FR.md` pour le détail par finding. Notes spécifiques à ce doc FULL :

### Pourquoi une release cleanup séparée

v0.5.7 a explicitement shippé 6 fixes (3 important + 3 minors triviaux) et explicitement déféré 5 mineurs cosmétiques avec breadcrumbs fichier:ligne dans le changelog. Deux paths étaient possibles :
1. Bundler les 5 minors dans v0.6.0 (le prochain bump majeur).
2. Les shipper comme release cleanup focalisée v0.5.8.

Option 2 choisie parce que :
- v0.6.0 est réservée pour les **splits architecturaux #13 + #14** (ssh.py 1324L + cron.py 1223L) — bundler des minors cosmétiques non liés là diluerait le thème major-version.
- Les 5 minors sont minuscules et self-contained — colle au cadence "release petite focalisée" établie par la branche v0.5.x.
- Préserve la lignée findings audit propre : chaque finding du sub-agent audit v0.5.7 a une release qui l'adresse explicitement.

### Impact comportemental sur le wire

Zéro. Vérifié par :
- `pytest -q` 4571 → 4583 (+12, tous verts) sans aucun échec ou rename de test existant
- `_Schedule.WEEKDAYS` compare égal à int brut 2 (préserve toute sémantique `if choice == _Schedule.X:`)
- `_is_finding_continuation` est strictement plus strict que le prédicat précédent `startswith("    ")`, mais le cas over-greedy contre lequel il se défend ne survient que quand un délimiteur de section se trouve être indenté 4-espaces (pas le cas dans aucune sortie BOB actuelle)
- Correction cursor-shift M-2 ne change la position d'affichage qu'après des multi-sélection deletes mélangeant items avant+après le cursor — jamais observé comme plainte utilisateur, mais sémantiquement un vrai fix
- Lift d'import `datetime` est un changement structurel pur

### Design du helper M-7

Le nouveau helper `_is_finding_continuation(line)` est intentionnellement conservateur : il rejette TOUTE ligne indentée qui contient un marker de finding ou commence par un glyphe de section. Alternatives considérées :
- **Regex anchored** comme `re.match(r"^    (?!\[ALERT\]|\[WARN\]|\[OK\]|\[INFO\])", line)` — marche mais moins lisible
- **Tracking niveau d'indentation** (une continuation doit être PLUS indentée que le parent finding) — overengineered pour le problème réel
- **Sentinelle empty-line** (stop seulement sur les blank lines) — trop permissif ; ne catcherait pas le cas over-greedy flagged par l'agent

Le design choisi est direct : lister les patterns qui appartiennent obviously à un autre parent, et stopper là. Facile à étendre si un nouveau glyphe de frontière apparaît (juste ajouter au tuple).

### M-5 IntEnum vs constantes module-level

Trois formes considérées :
- **Constantes `int` module-level** (`_SCHEDULE_DAILY = 1; ...`) — plus simple, mais pas d'introspection ou garanties de class-membership
- **`Enum`** — type le plus fort, mais casse les comparaisons `choice == 2` sauf à utiliser `.value`
- **`IntEnum`** — choisi parce qu'il compare égal à int brut (préservant chaque call site existant intouché) ET fournit des noms explicites

Coût : un import stdlib (`from enum import IntEnum`). Zéro overhead runtime.

### M-8 follow-up : le sweep des imports locaux non utilisés

Lifter `from datetime import datetime` dans `bob/cron.py:_run_install_cron_plain` a aussi révélé deux autres imports locaux redondants dans la même fonction : `import os` et `from pathlib import Path` étaient déjà au scope module. Retirés dans le même commit (petit mais clarté cumulative).

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4583 passed in ~6s
```

**4571 → 4583 (+12).** Nouvelles classes de tests :

`tests/test_cron.py` :
- `TestScheduleIntEnum` (2) — `_Schedule.DAILY == 1`, `_Schedule.WEEKDAYS == 2`, etc., plus parité comparaison IntEnum-vs-int.
- `TestDatetimeImportLifted` (3) — `bob.cron.datetime` est `datetime.datetime` ; idem pour `bob.tui.cron.datetime` ; smoke test `build_script_content` stamp toujours la date du jour.

`tests/test_manage_logs.py` :
- `TestCursorShiftAfterDelete` (2) — cas mixte avant/après (cursor shift par before-count seulement) ; cas all-after (cursor inchangé).
- `TestSummaryStartSentinel` (1) — détection SEP62-à-index-0 synthétique.
- `TestIsFindingContinuation` (4) — accepte body lines indentées ; rejette non-indentées ; rejette markers `[ALERT]`/`[WARN]`/`[OK]`/`[INFO]` indentés ; rejette délimiteurs de section indentés (`┌`/`└`/`━`/`╔`).

### Diff net

| Fichier | Delta |
|---|---|
| `bob/cron.py` | -3 / +1 (M-8 : 1 import top-level, 2 lignes import local retirées ; aussi retiré `import os` / `from pathlib import Path` locaux redondants dans `_run_install_cron_plain`) |
| `bob/tui/cron.py` | -2 / +12 (M-5 : définition classe `IntEnum` ; M-5 : 4 call sites mis à jour ; M-8 : 1 import top-level, 1 ligne import local retirée) |
| `bob/manage_logs.py` | -3 / +24 (M-2 : tracking deleted_before_cursor ; M-6 : sentinelle `None` ; M-7 : nouveau helper `_is_finding_continuation` + 2 call sites mis à jour) |
| `tests/test_cron.py` | +49 (TestScheduleIntEnum + TestDatetimeImportLifted) |
| `tests/test_manage_logs.py` | +94 (TestCursorShiftAfterDelete + TestSummaryStartSentinel + TestIsFindingContinuation) |
| Bump version + changelogs | ~17 fichiers standard |

### Compatibilité

- **Contrat JSON** : `schema_version="1"`, les 116 EXPLAIN_KEYS — inchangés.
- **Score par domaine** : inchangé. Score global inchangé.
- **Sortie wire** : inchangée.
- **API externe** : 2 nouveaux symboles module-level (`bob.tui.cron._Schedule` et `bob.manage_logs._is_finding_continuation`). Les deux leading-underscore = internes/semi-publics. Aucun retrait.
- **Keybindings** : inchangés.
- **Fallback no-curses** : inchangé.

### Campagne deep-audit v0.5.x — RÉSUMÉ FINAL

| Release | Scope | Findings shippés | Tests |
|---|---|---|---|
| v0.5.5 | 22 modules core (deep) + ~15 spot-checkés | 19 (4C + 4I + 11M) | +7 |
| v0.5.6 | `bob/checks/logs.py` (662L) | 10 (0C + 2I + 8M) | +15 |
| v0.5.7 | `bob/manage_logs.py` + `bob/tui/cron.py` (~1920L) | 6 shippés + 5 déférés | +11 |
| **v0.5.8** | **Les 5 mineurs déférés de v0.5.7** | **5 (tous mineurs)** | **+12** |

**Cumul** : 25 modules deeply audités + ~25 spot-checkés. 0 finding critique en suspens sur la branche. Croissance test nette depuis baseline v0.5.4 : 4538 → 4583 (+45 sur 4 releases hardening).

### Et après (v0.6.0)

Le bump major-version est réservé pour :
- **#13** : split `bob/checks/ssh.py` (1324 LoC)
- **#14** : split `bob/cron.py` (1223 LoC après le lift d'import v0.5.8)
- Unification prompt TUI (`_curses_readline` / `prompt_wizard` / `_rl` forment une hiérarchie 3-tier qui pourrait être aplatie)
- Cadence schema JSON v2 optionnelle (pas de breaking changes encore mais plan documenté)

Les deux splits de fichiers sont délibérément déférés depuis v0.5.x parce que gain × risque ne justifiait pas le churn dans une release minor contract-preserving.

---

## [v0.5.7] — 24-05-2026

**Passe de hardening ciblée sur le TUI curses.** Les deux modules curses interactifs (`bob/manage_logs.py` 999 LoC + `bob/tui/cron.py` 920 LoC = ~1920 LoC) explicitement déférés par les audits v0.5.5 et v0.5.6. Un sub-agent focalisé a audité les deux modules en intégralité. 11 findings : 0 critique, 3 important, 8 mineur (3 shippés + 5 déférés à v0.5.8).

Voir `CHANGELOG_FR.md` pour le détail par finding. Notes spécifiques à ce doc FULL :

### Méthodologie audit — deuxième passe TUI-only

Cette release complète la campagne audit 2-pass sur le bucket déféré par v0.5.5. Le pattern (sub-agent single-domain + exclusions explicites des findings déjà shippés) hérité de v0.5.6 et tuné avec deux ajouts pour le code curses :

1. **Callout frozen-contracts en tête** : keybindings (`q`/`r`/`h`/flèches/`Enter`/`Esc`), fallback no-curses (`BOB_NO_CURSES` env + branche `sys.stdout.isatty()`), exit codes (0/1/130), schéma JSON, système de profiles. Sub-agent a confirmé tous intacts après l'audit.
2. **Chasse à la classe de bugs v0.5.6** : scan actif des sites de comparaison `datetime.now()`. Résultat : un seul site (`bob/tui/cron.py:712`, génération timestamp header, pas de comparaison) — clean.

### Distribution ROI : 0 critique (encore)

Comme v0.5.6, aucun finding critique. Le TUI curses a été extensivement exercé en production sur le cycle v0.5.x (5 releases × 5 VMs cross-distro) et v0.5.5 #M-2 a récemment retiré du dead code curses (`_NullReport`). Les concerns high-risk (path traversal, shell injection, atomic writes ailleurs) déjà adressés par les passes précédentes.

Les 3 findings important sont tous de vrais bugs mais avec impact contraint :
- **I-1** uniquement UX-corrompant — la validation downstream prévient la propagation
- **I-2** uniquement exit-cleanliness — le path Ctrl-D était déjà un geste "je veux sortir"
- **I-3** un vrai gap d'atomicité avec basse fréquence (les réécritures cron sont rares, coupure de courant pendant encore plus) mais un haut blast radius (cessation silencieuse d'audit)

### Lignée des classes de bugs : atomic write + gestion EOFError

**I-3** amène le contrat atomic-write à son état final à travers le codebase. Après :
- v0.5.5 #C-1 (régression mode `apply_cron_email`)
- v0.5.5 #I-1 (enforcement mode 0o600 `recurrence.py` / `ignore.py`)
- v0.5.7 #I-3 (`apply_cron_schedule` → `_atomic_write`)

…tous les sites de mutation de fichier dans BOB passent maintenant par `_atomic_write(path, content, mode=)`. Les audits futurs peuvent utiliser un grep unique (`grep -rn "os\.open.*O_TRUNC\|open(.*'w'" bob/`) pour vérifier l'absence de régression.

**I-2** amène le contrat EOF de lecture interactive à son état final. Après :
- helper v0.5.0 `_rl()` (gestion EOF propre pour les wizards principaux)
- helper v0.5.4 `prompt_wizard()` (prompt translation-agnostic avec cancel)
- v0.5.7 #I-2 (les 3 sites `input()` bruts restants dans `manage_logs.py`)

…tous les sites de lecture interactive dans BOB routent maintenant EOF vers la sémantique chaîne-vide. Ctrl-D ne crash jamais ; Ctrl-C continue à exit 130 via le default Python.

### Mineurs déférés : liste explicite defer pour v0.5.8

Les 5 mineurs déférés trackés ici pour référence d'auditeur futur :

| # | Fichier:Ligne | Description |
|---|---|---|
| M-2 | `manage_logs.py:871` | `cursor = max(0, cursor - deleted)` suppose toutes les suppressions sont avant le cursor — si items marqués sont après, cursor bouge à gauche à tort |
| M-5 | `tui/cron.py:212` | `_, _SCHEDULE_WEEKDAYS, _SCHEDULE_MONTHDAYS, _SCHEDULE_CUSTOM = 1, 2, 3, 4` — assignment magic-number ; promote à `IntEnum` module-level |
| M-6 | `manage_logs.py:520-523` | `if summary_start: break` traite index 0 comme "pas de séparateur trouvé" — utiliser sentinelle `None` |
| M-7 | `manage_logs.py:536, 545` | `while ... lines[j].startswith("    ")` over-greedy : avale des lignes body 4-espaces non liées |
| M-8 | `tui/cron.py:711` + `bob/cron.py:761` | `from datetime import datetime` local au body de fonction — remonter au top du module |

Tous cosmétique / unreachable / layout-only. Zéro changement de comportement en v0.5.8 (quand shippé).

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4571 passed in ~6s
```

**4560 → 4571 (+11).** Nouvelles classes de tests :

`tests/test_cron.py` :
- `TestApplyCronScheduleAtomic` (2) — pin régression I-3. Spy sur `_atomic_write` pour vérifier qu'il est appelé ; simule échec pour vérifier que le contenu original du fichier cron survit intact.
- `TestIsPrintableInputChar` (4) — pin régression I-1. Vérifie la frontière à travers ASCII imprimable, Latin-1 imprimable, caractères de contrôle, et la plage complète des constantes `curses.KEY_*`.

`tests/test_manage_logs.py` :
- `TestEOFErrorOnPromptPath` (2) — pin régression I-2 dans `prompt_path()` avec et sans `allow_cancel`.
- `TestEOFErrorOnMoveConfirm` (1) — pin régression I-2 dans la branche move-logs `[y/N]` (Ctrl-D == decline).
- `TestEOFErrorOnDeleteAllConfirm` (1) — pin régression I-2 dans la branche delete-all `[y/N]` (Ctrl-D == cancel, fichier PAS supprimé).
- `TestDeletedOneCorrectName` (1) — pin logique M-1 : sous échecs unlink sélectifs, le nom affiché est le PREMIER fichier effectivement supprimé, pas `pending_delete[0]`.

### Diff net

| Fichier | Delta |
|---|---|
| `bob/cron.py` | -6 / +5 (I-3 swap `os.open` brut → `_atomic_write`) |
| `bob/tui/cron.py` | +20 / -10 (helper I-1 + appel filter, cleanup dead-code M-3, consolidation import M-4) |
| `bob/manage_logs.py` | +24 / -3 (I-2 trois catches EOFError, tracking deleted_name M-1) |
| `tests/test_cron.py` | +95 (TestApplyCronScheduleAtomic + TestIsPrintableInputChar) |
| `tests/test_manage_logs.py` | +90 (4 nouvelles classes de tests pour I-2 + M-1) |
| Bump version + changelogs | ~17 fichiers standard |

### Compatibilité

- **Contrat JSON** : `schema_version="1"`, les 116 EXPLAIN_KEYS — inchangés.
- **Score par domaine** : inchangé. Score global inchangé.
- **Sortie wire** : aucun changement à la sortie plain-text ou JSON. Les affichages TUI ne montrent plus de glyphes Grecs sur pression de touche de fonction (UX-visible uniquement).
- **API externe** : `_is_printable_input_char(ch_i)` est un nouveau helper module-level dans `bob/tui/cron.py`. Aucun retrait.
- **Keybindings** : inchangés. `q`/`r`/`h`/flèches/`Enter`/`Esc` se comportent identiquement.
- **Fallback no-curses** : inchangé. Mêmes branches `BOB_NO_CURSES` / `sys.stdout.isatty()`.

### Progrès closure audit v0.5.x (FINAL pour la passe deep-audit)

| Module | Statut | Release |
|---|---|---|
| 22 modules core (ssh.py, scoring.py, etc.) | audité (v0.5.5) | v0.5.5 |
| `checks/logs.py` | audité (v0.5.6) | v0.5.6 |
| **`manage_logs.py`, `tui/cron.py`** | **audité (v0.5.7, cette release)** | **v0.5.7** |
| Format renderers (`html/csv/markdown_output.py`) | spot-checké | — |
| `display.py`, `output.py` | spot-checké | — |
| ~25 autres modules `checks/*.py` (petits <300L chacun) | spot-checké | — |

**Campagne deep-audit branche v0.5.x fermée.** 25 modules deeply audités (3 passes × multiples sub-agents) + ~25 spot-checkés. Les 5 mineurs v0.5.7 déférés shipperont en v0.5.8 (release cosmétique-only).

### Roadmap

Après v0.5.8 (5 mineurs TUI déférés), la branche v0.5.x sera à son état final de maintenance. La prochaine version mineure (v0.6.0) est réservée pour les deux refactors architecturaux délibérément déférés du roadmap v0.5.x :
- **#13** : split `bob/checks/ssh.py` (actuellement 1324 LoC après la consolidation table `_BadDirective` v0.5.2)
- **#14** : split `bob/cron.py` (actuellement 1223 LoC après l'extraction des helpers de file-patching v0.4.8)

Les deux fichiers excèdent le soft ceiling 1000-LoC du projet ; les splits ont été déférés parce que gain × risque ne justifiait pas le churn dans une release minor contract-preserving. v0.6.0 est l'endroit approprié.

---

## [v0.5.6] — 24-05-2026

**Passe de hardening ciblée sur `bob/checks/logs.py`** — le module parser UFW logs (662 LoC) explicitement déféré par l'audit v0.5.5 à cause de sa densité regex. Un sub-agent focalisé a audité le module en intégralité (chaque fonction et branche). 10 findings shippés : 0 critique, 2 important, 8 mineur.

Voir `CHANGELOG_FR.md` pour le détail par finding. Notes spécifiques à ce doc FULL :

### Pourquoi une release single-module

La roadmap audit (fixée en notes clôture v0.5.5) avait `logs.py`, `manage_logs.py`, et `tui/cron.py` comme "not deeply audited". La décision était une campagne 2-passes :
- **v0.5.6** = `logs.py` (parser regex, haute densité bug)
- **v0.5.7** = `manage_logs.py` + `tui/cron.py` (curses TUI, user-visible)

Les releases single-module gardent le diff focalisé : 23 fichiers touchés (logs.py + tests + les 17 sites standard de bump version + 5 changelogs), un scope auditable. Plus facile à review que bundler tout le reste audit v0.5.x dans une seule v0.5.7.

### Findings audit : distribution ROI

L'audit a trouvé 10 issues mais **aucun bug critique**. Cela matche les attentes :
- Le module a déjà été touché par v0.5.x #8 (refactor `tuple` return) qui a forcé une review end-to-end de chaque code path
- Tests terrain sur 5 VMs sur 5 releases (v0.5.0 → v0.5.4) l'ont exercé en production
- Les concerns haut-risque (correctness regex, sémantique journald fallback, intégration GeoIP) étaient stables

Les 2 findings important (I-1 regex private-IP incohérente, I-2 year-rollover silent drop) sont de vrais bugs mais avec impact opérationnel faible sous conditions typiques. Les 8 mineurs sont des améliorations quality-of-implementation.

### Source unique de vérité : détection private-IP

I-1 ferme le dernier matcher private-IP hand-rolled du codebase. Après que v0.5.5 #I-4 ait réécrit `sysinfo._PRIVATE_IPV4_RE` pour utiliser des listes d'appartenance `ipaddress.ip_network`, `bob/checks/logs.py:46` restait le seul outlier avec sa propre regex ad-hoc. Le nouvel helper `_is_private_ip(ip)` dans `logs.py` délègue aux helpers sysinfo — il y a maintenant exactement un modèle pour "est-ce qu'cette IP est private/loopback/link-local" dans BOB.

### Classe de bug extraite : year-rollover sous clock skew

I-2 documente un pattern à watcher ailleurs dans le codebase :
> N'importe quelle logique de comparaison de date qui appelle `datetime.now()` pour décider si un timestamp parsé est "dans le passé" a besoin d'une fenêtre de tolérance (typiquement 5 minutes) pour absorber le jitter NTP, le log buffering, et le clock skew process. Un check `> now` strict drop silencieusement les données legitimate quasi-temps-réel.

Sites dans BOB qui utilisent `datetime.now()` pour comparaisons (résultat grep) :
- `bob/checks/logs.py:_parse_timestamp` — **corrigé en v0.5.6 (cette release)**
- `bob/checks/ssl_certs.py` — utilise `notAfter > now` pour expiry (direction correcte ; pas de rollback)
- `bob/checks/firmware.py` — utilise `last_update > now - days(N)` (direction correcte)
- `bob/checks/rkhunter.py`, `bob/checks/clamav.py`, `bob/checks/file_integrity.py` — comparaisons d'âge DB (direction correcte)

Aucun autre site n'a le même pattern year-rollover. Documenté dans le memory `project_v056_logs_audit.md`.

### Variante IPv6 `[UFW BLOCK6]`

M-1 attrape une variante non-documentée du préfixe UFW utilisée par certains packagers downstream (Debian backports, configs `before6.rules` custom). Le matcher substring les avait silencieusement droppées depuis des années. Impact terrain peu clair — la plupart des utilisateurs ne l'ont probablement jamais remarqué parce que le volume BLOCK IPv6 est dominé par le trafic link-local mDNS qui ne ferait pas surface comme un "finding manquant".

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4560 passed in ~6s
```

**4545 → 4560 (+15).** Tous nouveaux dans `tests/test_logs.py` :
- `TestPrivateIPDispatch` (8) — pin couverture régression I-1 incluant CGNAT, IPv6 link-local, ULA, input invalide
- `TestParseTimestampYearRollover` (3) — pin régression I-2 pour current-year, 1s-skew, vraie rollback Décembre
- `TestBlockPrefixMatcher` (3) — pin M-1 sur `[UFW BLOCK]`, `[UFW BLOCK6]`, rejet `[UFW ALLOW]`
- `TestProtoNormalisation` (1) — pin M-8 normalisation upper-case proto

### Diff net

| Fichier | Delta |
|---|---|
| `bob/checks/logs.py` | +60 / -25 (helper I-1 + tolérance I-2 + regex M-1 + ancre M-2 + reorder M-3 + helper cache M-5 + lecture binaire M-6 + M-7/M-8 minor) |
| `tests/test_logs.py` | +150 (4 nouvelles classes test) |
| Bump version + changelogs | standard ~17 fichiers |

### Compatibilité

- **Contrat JSON** : `schema_version="1"`, les 116 EXPLAIN_KEYS — inchangés.
- **Score par domaine** : inchangé. Score global inchangé.
- **Sortie wire** : 2 deltas étroits — lignes `[UFW BLOCK6]` maintenant comptées (précédemment droppées), et `_count_available_days` ne sur-compte plus sur logs locale non-anglais.
- **API externe** : `_is_private_ip(ip)` est un nouveau helper semi-public dans `logs.py`. La constante regex non-documentée `_PRIVATE_IP` est retirée.

### Progression clôture audit v0.5.x

| Module | Statut | Release |
|---|---|---|
| 22 modules core (ssh.py, scoring.py, etc.) | audités (v0.5.5) | v0.5.5 |
| `checks/logs.py` | **audité (v0.5.6, cette release)** | **v0.5.6** |
| `manage_logs.py`, `tui/cron.py` | pending | v0.5.7 |
| Format renderers (`html/csv/markdown_output.py`) | spot-checked (I-3 en v0.5.5) | — |
| `display.py`, `output.py` | spot-checked | — |
| ~25 autres modules `checks/*.py` (petits <300L chacun) | spot-checked | — |

---

## [v0.5.5] — 24-05-2026

**Passe de hardening — post-v0.5.4 audit par un sub-agent général-purpose profond.** 19 findings : 4 bugs réels (C-1 à C-4), 4 security smells (I-1 à I-4), 11 cleanups mineurs (M-1 à M-11). 17 fixés avec changements code/test ; 2 sont commentaires doc (M-8/M-9). Commit cosmétique compagnon (M-6) migre le typing `Optional[X]` / `List[X]` sur 18 modules.

### Méthodologie audit

Un sub-agent général-purpose a fait une lecture profonde de 22 modules (`bob/cron.py`, `bob/checks/ssh.py`, `bob/checks/services_state.py`, `bob/scoring.py`, `bob/domain_scores.py`, `bob/explain.py`, `bob/__main__.py`, `bob/sysinfo.py`, `bob/fixes.py`, `bob/recurrence.py`, `bob/compare.py`, `bob/ignore.py`, `bob/correlation.py`, `bob/i18n.py`, `bob/watch.py`, `bob/webhook.py`, `bob/checks/_run.py`, `bob/report_markdown.py`, `bob/checks/updates.py`, `bob/checks/password_policy.py`, `bob/checks/user_accounts.py`, `bob/checks/file_perms.py`) + 15+ modules spot-checkés. Findings remontés en sévérité-graded (C / I / M / S) avec file:line, cause racine, fix recommandé, risque régression. Couverture rapportée dans l'audit (listes full / spot / not-touched).

Modules non profondément auditées (déférés pour passes futures) : `bob/manage_logs.py` (999L curses TUI), `bob/tui/cron.py` (920L curses TUI), `bob/checks/logs.py` (662L regex UFW), `bob/display.py`, `bob/output.py`, formats `bob/html_output.py` / `bob/csv_output.py` / `bob/markdown_output.py`.

### Bugs critiques (4)

**C-1 — `apply_cron_email()` cassait silencieusement les audits programmés**

`bob/cron.py:apply_cron_email()` (lignes 863-900) réécrivait à la fois `entry.cron_path` et `entry.script_path` via `_atomic_write()`, qui ouvrait toujours le fichier temp avec mode `0o600`. Après `os.replace()` le nouveau fichier héritait de ce mode — le wrapper script (originellement `0o755`) perdait son bit exécutable, et cron silencieusement ne pouvait plus l'exec. N'importe qui ayant utilisé `bob --manage-cron` pour changer son email de notification entrait dans cet état. Cron continuait à lire le cron file mais le script ne tournait plus ; l'audit programmé devenait silencieusement dark.

Le pattern était hérité de quand `_atomic_write` a été introduit (fichiers state privés, `0o600` correct). Les callers cron.py ajoutés plus tard n'ont pas tenu compte de la différence de mode.

```python
def _atomic_write(path: Path, content: str, mode: int = 0o600) -> None:
    """Write *content* to *path* atomically (temp file + os.replace).

    *mode* is the open() flag mode for the *new* file. Default is 0o600
    (private) — appropriate for state files. Callers patching existing
    cron files (0o640) or wrapper scripts (0o755) MUST pass the right
    mode explicitly, otherwise os.replace() preserves the tmp file's
    mode (0o600) and breaks the original file's permissions.
    """
    ...
```

Deux call sites `apply_cron_email` mis à jour : `mode=0o640` pour cron file, `mode=0o755` pour script. Test régression ajouté : `tests/test_cron.py::TestApplyCronEmail::test_preserves_script_executable_mode` pin le mode résultant après la réécriture. La recommandation audit S-2 ("test for permission preservation on cron-managed files") est maintenant satisfaite.

**C-2 — `password_policy.no_quality_module` cmd non-fixable via `--fix --apply`**

`bob/checks/password_policy.py:184-192` émettait `cmd="sudo apt install libpam-pwquality && sudo pam-auth-update"` avec `nature="action"`. `bob/fixes.py:106` (`_has_shell_ops`) flagge correctement `&&` comme syntaxe shell unsafe et rejette le cmd au moment du fix avec "unsafe shell syntax in command". L'utilisateur pressait `y` et ne voyait rien se passer.

`apt install … && pam-auth-update` 2-étapes n'est de toute façon pas chainable en un seul `subprocess` exec (l'install pkg peut échouer ; pam-auth-update a besoin de voir le nouveau pkg). Demotion à `nature="improvement"` pour que le cmd apparaisse comme guidance sans entrer dans la queue fix. Test `test_nature_is_improvement` remplace `test_nature_is_action`.

**C-3 — `password_policy.weak_minlen` cmd décoratif, pas exécutable**

`cmd="sudo nano /etc/security/pwquality.conf  →  minlen = 8"` — la flèche Unicode `→` tokenise via `shlex.split()` en junk : `["sudo", "nano", "/etc/security/pwquality.conf", "→", "minlen", "=", "8"]`. Même si ça parsait, c'est un *hint de guidance avec next-step embedded*, pas une commande. Même classe de fix que C-2 : demotion à `nature="improvement"`.

**C-4 — Drift `EXPLAIN_KEYS` pour `services_state`**

Drift de renommage. `bob/checks/services_state.py:197,204,211` émet des findings avec `key="services_state.service_inactive"`. `bob/explain.py:151` déclare l'EXPLAIN_KEY canonique `services_state.enabled_inactive`. Le bloc locale `explain.services_state.enabled_inactive` décrit le bon concept. Le drift fait que `bob --explain services_state.service_inactive` retourne "key not found" — alors que l'utilisateur vient de voir cette clé dans sa sortie audit.

Deux options sur la table :
- **(a)** Renommer la clé émise dans `services_state.py` pour matcher le nom canonique. **Casse le contrat JSON output** pour n'importe quel utilisateur automatisant sur la clé `service_inactive` (JSON `schema_version="1"` inclut les finding keys).
- **(b)** Ajouter `services_state.service_inactive` → `services_state.enabled_inactive` à `EXPLAIN_KEY_ALIASES`. JSON output inchangé. `--explain` résout via alias.

Option (b) choisie (conservatrice). Test régression `test_services_state_alias_routes_to_canonical` ajouté pour lock l'alias.

### Important issues (4)

**I-1 — `recurrence.json` + `ignore.yml` écrits avec umask par défaut**

`bob/recurrence.py:56-57` utilisait `tmp.open("w", encoding="utf-8")` et `bob/ignore.py:89` utilisait `path.write_text(content, encoding="utf-8")`. Les deux s'appuyaient sur l'umask process. Sur Debian/Ubuntu par défaut l'umask est `0022`, produisant des fichiers world-readable `0644`. **Tous les autres fichiers state persistants dans BOB** (`bob/config.py:123`, `bob/compare.py:185`, `bob/history.py`, `bob/report.py:160`, `bob/manage_logs.py`) utilisent `os.open(..., 0o600)` via soit `_atomic_write` soit `os.fdopen` explicite — un invariant documenté `~/.config/bob/`. SNAPSHOT.md flagge cela explicitement.

Les données ne sont pas haute sensibilité (clés finding récurrentes, clés finding ignorées) mais l'incohérence viole l'invariant. Les deux corrigés pour utiliser `os.open(str(path), os.O_WRONLY|os.O_CREAT|os.O_TRUNC, 0o600)` + `os.fdopen()`.

**I-2 — `_apply_deduction` bypassait le cap de score après `finalize()`**

Le contrat orchestrateur documenté à `bob/scoring.py:437-446` est one-way : `finalize()` bake-in le cap puis set `_finalized=True`. Un `engine.apply(result)` tardif muterait `_raw_score` via `_apply_deduction` après que le cap était appliqué — bypassant silencieusement. Pas de guard.

Guard défensif ajouté à `bob/scoring.py:541-548` :

```python
def _apply_deduction(self, deduction: Deduction) -> None:
    if self._finalized:
        logger.warning(
            "ScoreEngine: deduction %r applied after finalize() — discarded "
            "to preserve cap semantics. Re-order callers if intentional.",
            deduction.key or deduction.reason[:40],
        )
        return
    self._raw_score -= deduction.points
    self.breakdown.append(deduction)
```

Le path production appelle toujours `finalize()` en dernier donc ce guard est défensif. Test régression `test_post_finalize_deduction_is_discarded` pin à la fois le discard et le log WARNING.

**I-3 — `_safe_url` permettait injection `"` dans HTML email href attribut**

`bob/report_markdown.py:_inline_format()` (lignes 446-468) html-escape le texte d'abord (avec `quote=False` par défaut), puis re-substitue `[label](url)` en `<a href="url">label</a>`. L'URL est le 2e groupe regex — déjà html-escapée, mais avec `quote=False` seulement, donc `"` et `'` restent raw. `_safe_url(url)` (ligne 436) ne vérifiait que le préfixe de scheme URL et retournait l'URL non modifiée dans le contexte attribut.

Chaîne d'attaque : un markdown link craft dans un texte user-controllable (ex. label plugin `services.d/*.json` malveillant, ou string traduit avec markdown dedans) :
```
[label](https://x.com" onclick="alert(1))
```

Après `html.escape()` l'URL devient `https://x.com&quot; onclick=&quot;alert(1)` (seulement `&` escapé car `quote=False` laisse `"` tranquille). Hmm — en fait avec `html.escape` Python par défaut, `"` est converti à `&quot;` SEULEMENT quand `quote=True`. Avec `quote=False` (le default) `"` reste raw → c'est le vecteur. L'URL avec `"` raw atterrit dans `href="…"` → breakout attribut → injection JavaScript.

Fix : `_safe_url` fait maintenant `html.escape(url, quote=True)` pour encoder n'importe quel `"`/`'`/`<`/`>` resté dans l'URL. Re-escape est safe (double-escape produit `&amp;quot;` que les browsers décodent une fois en `&quot;` — un littéral dans la valeur URL, pas de syntaxe active).

Nouveau fichier de test `tests/test_report_markdown_safety.py` avec 9 assertions régression (passthrough URL, rejet scheme, escape double-quote, escape single-quote, escape angle-bracket, full-pipeline test attack-string).

Surface d'attaque réaliste étroite (le corps HTML de l'email est rendu dans le mail client de l'utilisateur ; les seuls strings user-controllable atteignant `_inline_format` sont les strings locale traduits et les labels service plugin-définis). Mais le fix est cheap et le rapport email est maintenant XSS-safe-by-construction.

**I-4 — `sysinfo._PRIVATE_IPV4_RE` brittle + Python 3.12+ aurait cassé un switch stdlib**

Deux problèmes compoundés :
1. Le call site à `bob/sysinfo.py:192` faisait `re.search(r"via\s+" + _PRIVATE_IPV4_RE.pattern.removeprefix("^"), result.stdout)` — manipulant l'attribut `.pattern` d'un pattern compilé via concaténation string. Drop les flags compile originaux.
2. Un switch naïf vers `ipaddress.IPv4Address.is_private` de stdlib casserait sur Python 3.12.4+ : la définition de `is_private` s'est élargie pour inclure les ranges documentation/reserved (`192.0.0.0/29`, `192.0.2.0/24`, `198.51.100.0/24`, **`203.0.113.0/24`**, `198.18.0.0/15`, etc.). Les tests utilisant des IPs documentation (`tests/test_sysinfo.py` utilise `203.0.113.5` comme exemple "public") classifieraient soudain ces ranges comme "local". Attrapé seulement après la première tentative de refactor qui a fail.

Fix final : tuples explicites `_PRIVATE_IPV4_NETS` + `_PRIVATE_IPV6_NETS` d'objets `ipaddress.ip_network`. Helpers `_is_private_or_loopback_ipv4()` / `_is_private_or_loopback_ipv6()` utilisent appartenance `addr in net`. Couvre :
- IPv4 : RFC 1918 (10/8, 172.16/12, 192.168/16), loopback (127/8), link-local (169.254/16), CGNAT (100.64/10)
- IPv6 : loopback (::1/128), link-local (fe80::/10), ULA (fc00::/7)

Les ranges documentation/reserved restent "public" donc `detect_network_context()` les identifie correctement comme nécessitant une recherche IP publique.

### Cleanups mineurs (11)

| # | Fix | Fichiers affectés |
|---|---|---|
| **M-1** | Regex email unifiée via `bob.config._EMAIL_RE` (dupliquée en module-level + littéral inline × 3 sites) | `bob/cron.py` |
| **M-2** | `bob/watch.py:_NullReport` retiré → use `bob.report.NullReport` (Report Protocol canonique introduit en v0.5.0 #10). L'ancien magic `__getattr__` 5-lignes ad-hoc était exactement le genre de drift duck-typed que l'introduction Protocol était censé prévenir. | `bob/watch.py`, `tests/test_watch.py` |
| **M-3** | 3 clés locale mortes retirées : `_meta.lang`, `_meta.version` (manifest metadata pour un outil non-existant), `ignored.hint` (test-only, jamais wiré dans le display production). | `bob/locales/{en,fr}.json`, `tests/test_ignore.py` |
| **M-4** | Règle `corr.fully_blind` avait `all_of={"firewall.logging_off", "fail2ban.not_installed"}` — exigeait `not_installed` mais ignorait `fail2ban.service_inactive`. Règle sœur `corr.stale_unmonitored` accepte déjà les deux via `any_of`. Élargie pour fire quand firewall est aveugle AND n'importe quel layer de détection (fail2ban ou auditd, dans l'un ou l'autre état) est aveugle. | `bob/correlation.py`, `tests/test_correlation.py` |
| **M-7** | Extraction helper `_has_actionable_findings()` + frozenset `_TRANSPARENCY_KEYS` dans `updates.py`. Le filter inline `any(f.key != "updates.apt_cache_age" for f in result.findings)` était fragile — ajouter un 2e INFO transparence changerait silencieusement la sémantique "all clear". Le helper + frozenset future-proof. | `bob/checks/updates.py` |
| **M-8** | Commentaire seul — clarifie pourquoi `_parse_config_file` s'arrête aux Match blocks ET skippe silencieusement les `Include` suivants. Choix défensif intentionnel (modéliser le contexte conditionnel Match safely est hors scope) ; le flag `_match_block=True` surface ça à l'utilisateur via l'INFO existant `ssh.match_block`. | `bob/checks/ssh.py` |
| **M-9** | Commentaire seul — clarifie que les champs vides `ListeningPort.process`/`iface` veulent dire "inconnu" (quand `ss -p` manque le privilège ou est indisponible), pas "pas de processus". `is_all_interfaces` en tient déjà compte. | `bob/checks/ports.py` |
| **M-10** | Regex `apply_cron_schedule` resserrée : ancre premier champ changée de `^\S+` à `^[0-9*,\-/]\S*` (shape cron-token). Les comment lines commençant par `#` ne matchent plus — précédemment un commenté `# 0 3 * * * root /usr/bin/legacy-bob` aurait été réécrit silencieusement. | `bob/cron.py`, `tests/test_cron.py` |
| **M-11** | Cmd `services_state.service_inactive` contenait `&& sudo journalctl …` — même rejet shell-op que C-2. Drop le journalctl du cmd (diagnostic, pas part du fix restart) et déplacé la suggestion en `note=` pour guidance. | `bob/checks/services_state.py` |

### M-6 (commit séparé) — `Optional[X]` / `List[X]` → `X | None` / `list[X]`

Sweep mécanique pur sur 18 modules. Syntaxe Python 3.10+ (minimum du projet). Déjà utilisée dans les modules récents introduits durant v0.5.x. Cela unifie le codebase sur une forme.

Commit isolé pour deux raisons :
1. **Safety revert** — si un search-and-replace mécanique introduit un typo (ex. un `Optional[X]` dans un docstring quoted incorrectement converti), le commit cosmétique peut être reverté sans perdre les fix bugs Waves 1-3.
2. **Review hygiene** — bug fixes et changements typing cosmétiques ont des concerns de review différents. Les bundler dans un commit obscurcit le diff.

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4545 passed in ~7s
```

**4538 → 4545 (+7).** Nouveaux tests :
- `tests/test_cron.py::test_preserves_script_executable_mode` (C-1)
- `tests/test_explain.py::test_services_state_alias_routes_to_canonical` (C-4)
- `tests/test_scoring.py::test_post_finalize_deduction_is_discarded` (I-2)
- `tests/test_report_markdown_safety.py` — nouveau fichier avec 9 tests régression (I-3)
- `tests/test_correlation.py::test_fires_with_only_fail2ban_inactive` + `test_does_not_fire_when_firewall_logging_present` (M-4)
- `tests/test_cron.py::test_comment_line_with_root_token_not_modified` (M-10)

Tests supprimés :
- `tests/test_watch.py::TestNullReportIsolation` (5 tests — magic `__getattr__` obsolète de l'ancien `_NullReport`)
- `tests/test_watch.py::TestNullReport::test_any_method_returns_none` + `test_attribute_access_returns_callable` (2 tests — même raison)
- `tests/test_ignore.py::test_hint_key_en` (1 test — clé locale supprimée)

Tests renommés : `test_nature_is_action` → `test_nature_is_improvement` (× 2 dans `tests/test_password_policy.py`).

### Compatibilité

- **Contrat JSON** : `schema_version="1"` et les 116 EXPLAIN_KEYS inchangés. C-4 utilise `EXPLAIN_KEY_ALIASES` (additif) — clés JSON output préservées ; `--explain` route via alias.
- **Score par domaine** : inchangé. Score global sur host dev (so6desktop) : 8/10 → 8/10. Le score *display* shifte légèrement : sur les hosts sans `pam_pwquality`, le finding password_policy se déplace du bloc "À corriger" (action) à "Améliorations possibles" (improvement). Changement visuel, pas changement de score.
- **Diff sortie wire** : visible seulement sur les hosts hittant les findings demotés-à-improvement (password_policy.no_quality_module + .weak_minlen, services_state.service_inactive — ce dernier change seulement la shape `cmd`, pas la nature). Tous les autres hosts voient une sortie identique.
- **API externe** : aucun breaking change. `_atomic_write` (prend maintenant `mode=` kwarg) et `EXPLAIN_KEY_ALIASES` (a maintenant une entrée) sont additifs.
- **i18n** : 3 clés locale retirées (vérifié via AST scan locale-coverage + `grep` manuel).

### Où v0.5.5 se situe dans la ligne v0.5.x

Ceci est une **release de maintenance** pour la branche v0.5.x, post-cycle hardening. La branche refactor de 5 releases (v0.5.0 → v0.5.4) a clos le 2026-05-23 avec les 13/15 findings audit shippés + 2 splits déférés v0.6.0. v0.5.5 adresse un audit 19-findings séparé focalisé sur les **dimensions hardening** (bugs réels, security smells, code health) plutôt que refactor structurel.

La ligne v0.5.x s'engage à rester contract-preserving. Deferrals pour v0.6.0 incluent #13 (split ssh.py, 1324 LoC), #14 (split cron.py, 1224 LoC), et tout cleanup breaking-change que le prochain cycle audit fait apparaître.

---

## [v0.5.4] — 23-05-2026

**Refactor v0.5.x — Phase 5 sur 5 (finale, ferme l'audit v0.5.x).** Trois findings d'audit clôturés (`#6`, `#9`, `#15b`), une feature métier demandée par l'utilisateur (cache APT option C), deux findings (`#13` split ssh.py, `#14` split cron.py) explicitement déférés à v0.6.0. Voir `CHANGELOG_FR.md` pour le détail par finding. Cette entrée `CHANGELOG_FULL_FR.md` mirror ce contenu et ajoute les notes de clôture de la branche v0.5.x.

### Synthèse branche v0.5.x (Phase 1 → 5)

| Phase | Version | Date | Titre | Delta LoC vs précédent |
|---|---|---|---|---|
| 1 | v0.5.0 | 21-05-2026 | Ouvre la branche — 6 helpers + couverture cron (+39 tests) + 1 fix bug latent | additif |
| 2 | v0.5.1 | 22-05-2026 | `warn_with_deduction()` — 120 sites sur 27 fichiers | **−519** |
| 3 | v0.5.2 | 22-05-2026 | Table `_BAD_DIRECTIVES` + callbacks `_sec()` | +27 |
| 4 | v0.5.3 | 22-05-2026 | `_LEVEL_DISPATCH` + helpers summary + retrait `log_data` | +40 |
| 5 | **v0.5.4** | **23-05-2026** | `prompt_wizard` + sunset + `_PREFIX_TO_DOMAIN` + cache APT C | +49 |
| **Total** | — | — | **13/15 findings audit + 1 feature métier + sunset + 1 deprecation** | **≈ −350 LoC vs v0.4.8** |

La branche v0.5.x a shippé sur **5 releases en 2 jours calendrier** (2026-05-21 à 2026-05-22). Les cinq releases testées cross-distro sur 5 VMs (Linux Mint 22.3 prod + Mint+DDNS, Debian 13 trixie, Kali Rolling, Ubuntu 26.04 LTS) avec zéro régression observée. Sortie wire préservée bit-pour-bit à travers les Phases 1–4 ; Phase 5 introduit 2 changements wire intentionnels (ligne INFO cache APT, re-bucketing scores par domaine) documentés ci-dessus.

### #6 — Helper `prompt_wizard()` pour wizards plain-text

`bob/_tty.py` expose un nouveau helper `prompt_wizard(label, *, default="")` qui wrappe `input()` avec le boilerplate wizard-step que chaque wizard plain-text devait répéter. La signature du helper est intentionnellement minimale — pas d'args `t` / `key` comme suggéré par `_prompt(t, key, validator)` de l'audit. Le caller pré-formate le label (déjà traduit) et gère la validation downstream. Cela garde le helper :

- **Idempotent** sous `patch("builtins.input", ...)` — les mocks de test existants continuent de fonctionner.
- **Translation-agnostic** — utilisable depuis n'importe quel contexte où un label est déjà disponible.
- **Composable** — la validation vit au site d'appel donc le helper ne porte pas de policy de retry.

```python
def prompt_wizard(label: str, *, default: str = "") -> "str | None":
    """Prompt wizard plain-text avec gestion uniforme cancel + default.

    Utilisez ``label="  > "`` quand la question a déjà été imprimée via
    :func:`print` (wizards multi-lignes). Utilisez un label inline complet
    (``"  Foo [{default}]: "``) pour les prompts single-line.

    Retourne :
        ``None`` — l'utilisateur a tapé ``q`` ou ``quit`` (case-insensitive).
        ``str``  — input trimmé, ou ``default`` si Enter pressé tout seul.
    """
    raw = input(label).strip()
    if raw.lower() in ("q", "quit"):
        return None
    return raw or default
```

Migration dans `bob/cron.py` :

- **Install wizard** (`_run_install_cron_plain`, lignes 470-595) : 5 sites `input()` → 5 appels `prompt_wizard()`. Le boilerplate pré-Phase-5 (`.strip()` + `.lower() in ("q","quit")` + fallback default) faisait 4-5 lignes par site ; post-migration c'est 2-3 lignes par site (appel helper + check `None`).
- **Edit wizard** (`edit_cron_schedule`, lignes 929-1009) : 4 sites `input()` → 4 appels `prompt_wizard()`. Le prompt schedule-type garde `read_line()` (raw-mode, Esc-aware) — asymétrie intentionnelle ; l'edit wizard a hérité de la navigation menu raw-mode de son contexte adjacent-curses, mais le reste de ses steps réutilise le helper plain-wizard pour la cohérence.

Sites NON migrés (sémantique différente) :

- `prompt_emails` confirmations y/n (4 sites lignes 414, 428, 432) : requièrent un `y` explicite vs n'importe quoi d'autre, pas de default-on-Enter.
- `_run_install_cron_plain` confirmation overwrite (ligne 589) : même pattern y/n.
- `manage_cron.email_store_enter` (ligne 708) : entrée nom standalone sans cancel.
- `manage_logs.prompt_path()` : déjà un wrapper higher-level autour de `input()` avec handling path-specific.

Après migration `cron.py` a 10 sites `input()` bruts restants (vs 20+ avant), tous des confirmations y/n ou prompts spécialisés.

### #9 — Sunset env var `UFW_AUDIT_SHARE` (REMOVED en v0.6.0)

Historique : BOB s'appelait à l'origine "UFW Audit" avant v0.1.0. L'env var de share-dir a gardé l'ancien nom malgré le renommage. v0.4.2 a introduit `BOB_SHARE` comme primaire documenté ; `UFW_AUDIT_SHARE` est resté accepté avec un diagnostic niveau INFO pour les packagers utilisant des scripts d'installation legacy.

v0.5.4 commit le timeline de deprecation :

| Changement | Avant (v0.5.3) | Après (v0.5.4) |
|---|---|---|
| Niveau log | `logger.info(...)` | `logger.warning(...)` |
| Message | "the legacy name will be dropped in a future major release" | "DEPRECATED since v0.5.4, will be REMOVED in v0.6.0" |
| Docstring module | "Will be dropped in a future major release." | "Deprecated since v0.5.4 and will be removed in v0.6.0." |

`SECURITY.md` liste déjà v0.5.x comme la ligne supportée actuelle et v0.4.x comme end-of-life (mis à jour en v0.5.3). Les packagers utilisant `UFW_AUDIT_SHARE` voient le warning de deprecation à chaque run BOB et ont un timeline clair avant v0.6.0.

### #15b — Mapping `_PREFIX_TO_DOMAIN` explicite pour 3 entrées catch-all v0.4.x

Background : `tests/test_domain_scores_mapping_complete.py` (#15a) en v0.5.0 a introduit un test AST-scan qui asserte que chaque prefixe de clé de finding émis est soit explicite dans `_PREFIX_TO_DOMAIN` soit whitelisté dans `_CATCH_ALL_BY_DESIGN`. La whitelist capturait l'état v0.4.x où certains prefixes tombaient silencieusement dans le catch-all `firewall` sans fit propre — flaggé pour review en #15b (Phase 5).

La review Phase 5 a choisi 3 prefixes pour réattribution explicite :

```python
# bob/domain_scores.py:_PREFIX_TO_DOMAIN contient maintenant :
"fail2ban":         "ssh",
"virt":             "hardening",
"docker_audit":     "hardening",
```

**Pourquoi ces trois :**

- `fail2ban` → `ssh` : Le jail le plus commun (et inclus par défaut) de Fail2ban est `sshd`. Les findings `fail2ban.*` dans `bob/checks/fail2ban.py` sont dominés par les signaux de protection SSH-bruteforce. Les bucketer sous `ssh` aligne l'impact score avec les jails configurés.
- `virt` → `hardening` : Le seul finding `virt.bypass_risk` dans `bob/checks/virtualization.py` détecte les bridges libvirt/KVM (virbr0 etc.) insérant des règles iptables qui bypassent la chaîne FORWARD d'UFW. C'est une préoccupation *kernel + stack iptables* — plus proche du durcissement système que de la config firewall.
- `docker_audit` → `hardening` : `bob/checks/docker.py` audite la *configuration* container (daemon.json `iptables=false`, durcissement container actifs) plutôt que l'exposition réseau docker firewall-level (qui vit sous le prefix `docker` et reste en firewall). La réattribution aligne la séparation des prefixes entre les deux préoccupations.

**Pourquoi PAS `smtp` / `desktop_apps` :**

- `smtp` : L'exposition SMTP locale (Postfix/Exim listening sur 127.0.0.1:25) est genuinely une question de surface d'attaque. Firewall est le fit le plus proche ; aucun domaine candidat ne promet mieux.
- `desktop_apps` : Inventaire INFO-only (liste les processus desktop détectés — ExpressVPN, kDrive, Brave, etc.). Pas d'impact scoring. Le rebucketer pour la cleanliness n'a pas de payoff — gardé dans catch-all avec justification explicite dans la whitelist de test.

**Impact score** (par domaine sur hosts émettant ces prefixes ; score global inchangé) :

- Hosts avec WARN `virt.bypass_risk` (KVM/libvirt installé, workstations dev) — voient `Pare-feu & Services` monter de 1 point, `Durcissement` descendre de 1 point.
- Hosts avec findings `fail2ban.*` (rare en pratique ; la plupart des findings fail2ban sont level OK promouvant le domaine SSH) — re-promotion au domaine `ssh`.
- Hosts avec findings `docker_audit.*` (Docker installé + findings audit, ex workstations dev avec daemon Docker) — déplacés vers `hardening`.

Changements de test dans `tests/test_domain_scores_mapping_complete.py` :

- 3 entrées retirées de `_CATCH_ALL_BY_DESIGN` : `fail2ban`, `virt`, `docker_audit`.
- 3 entrées restantes (`smtp`, `desktop_apps`, `prerequisites`) reçoivent des justifications rafraîchies — elles ne pointent plus vers un futur "review in v0.5.4" puisque #15b est maintenant fermé.
- Le bloc de commentaire au-dessus de `_CATCH_ALL_BY_DESIGN` mis à jour pour refléter que le catch-all v0.4.x a été reviewé (plus aucun candidat flaggé pour tightening).

### Cache APT option C — INFO permanent sur âge cache (feature métier demandée par user)

**Contexte (depuis test terrain v0.5.3).** Durant le test cross-distro le 2026-05-22, la VM Ubuntu 26.04 LTS (`so6ubuntutest`) rapportait "Les paquets système sont à jour" dans l'audit BOB, mais un `sudo apt update` manuel lancé immédiatement après révélait 17 paquets en attente (dont 8 LTS security updates : libgnutls30t64, bind9, openvpn, rsync, etc.). L'investigation a montré que la simulation `apt-get -s dist-upgrade` de BOB lisait correctement le cache APT local — mais le cache avait 3-5 jours d'âge (sous le seuil obsolète de 7 jours qui déclenche un WARNING) et n'avait pas été synchronisé avec l'upstream où des annonces de sécurité avaient landé entre-temps.

Le WARNING existant `apt_cache_stale` (>7 jours) couvrait le cas obviously-stale mais laissait la zone silencieuse "frais-assez-mais-pas-zéro" non-observable. L'utilisateur a choisi "option C" parmi 4 options proposées : *toujours* émettre un INFO avec l'âge du cache quand le verdict est "all clear", donnant une transparence permanente sur la fraîcheur du cache.

**Implémentation.** Insérée dans `bob/checks/updates.py:check_updates()` entre les checks de mise à jour en attente existants et l'émission OK "all clear" :

```python
# --- APT cache age (transparency when no findings security/regular) ----
# Le verdict "all clear" repose sur l'état du cache APT local. Surface
# l'âge du cache pour que l'utilisateur sache s'il regarde une lecture
# fraîche ou un snapshot obsolète. Le WARNING stale-threshold ci-dessus
# couvre déjà le cas > 7 jours — cet INFO couvre la zone "frais-assez
# mais pas zéro" que le seuil laisse silencieuse.
if (
    cache_age is not None
    and not security
    and not regular
    and cache_age * 86400 < _APT_CACHE_STALE_THRESHOLD
):
    result.info(
        message=_t("updates.apt_cache_age", days=cache_age),
        detail=_t("updates.apt_cache_age_detail"),
        key="updates.apt_cache_age",
    )

# --- All clear ----------------------------------------------------------
# findings peut être non-vide ici à cause de l'INFO cache-age ci-dessus ;
# le finding ok n'est émis que quand *aucun* signal n'a été produit.
if not any(f.key != "updates.apt_cache_age" for f in result.findings):
    result.ok(
        message=_t("updates.ok"),
        key="updates.ok",
    )
```

Subtilité : le check "all clear" `result.ok(...)` a changé de `not result.findings` (n'importe quel finding skippe le OK) à `not any(f.key != "updates.apt_cache_age" for f in result.findings)`. Cela préserve l'émission OK quand le seul finding présent est le nouveau INFO cache-age. Sans le changement, les hosts hittant cache APT C perdraient la ligne OK "Les paquets système sont à jour".

**Clés locale** ajoutées dans `bob/locales/en.json` + `bob/locales/fr.json` :

- `updates.apt_cache_age` (EN) : "APT cache age: {days} day(s) — run `sudo apt update` for a fresher read"
- `updates.apt_cache_age` (FR) : "Âge du cache APT : {days} jour(s) — `sudo apt update` pour une lecture plus fraîche"
- `updates.apt_cache_age_detail` : explication 1-paragraphe rappelant que BOB est read-only et pointant vers unattended-upgrades pour la fraîcheur automatisée.

**Quand l'INFO fire :**

| Condition | INFO émis ? |
|---|---|
| Système non-Debian (`apt` indisponible) | Non (chemin `updates.no_apt`) |
| Paquets de sécurité en attente | Non (WARN sécurité est le signal primaire) |
| Paquets réguliers en attente | Non (INFO régulier est le signal primaire) |
| Âge cache non lisible (`/var/cache/apt/pkgcache.bin` manquant) | Non |
| Âge cache ≥ 7 jours | Non (WARN `apt_cache_stale` le couvre déjà) |
| Âge cache 0–6 jours ET aucune mise à jour en attente | **Oui** (le cas cible option C) |

Validation terrain : sur le host dev (so6desktop) avec 4 paquets de sécurité en attente, l'INFO est correctement supprimé (WARN sécurité est le signal primaire). Sur un hypothétique box Ubuntu LTS idle fraîchement synchronisé, l'INFO afficherait "Âge du cache APT : 0 jour(s) — `sudo apt update` pour une lecture plus fraîche" — transparence-by-default.

### Deferrals : `#13` (split ssh.py) et `#14` (split cron.py) → v0.6.0

L'audit v0.5.x (2026-05-21) flagged les deux fichiers comme candidats au split :

```
bob/checks/ssh.py:  1387 LoC à v0.4.8 → 1268 après #1 (Phase 2) → 1324 après #4 (Phase 3) → 1324 à l'entrée v0.5.4
bob/cron.py:        1223 LoC à l'audit → 1223 après #6 (Phase 5)  → 1223 à l'entrée v0.5.4
```

La prédiction de l'audit était que les Phases 2 + 3 shrinkeraient ssh.py sous 1000 LoC, rendant le split inutile. L'état final est 1324 LoC — Phase 2 (`warn_with_deduction`) a coupé 119 lignes mais Phase 3 (`_BAD_DIRECTIVES`) a ajouté 56 (verbosité table compense le shrinkage impératif).

**Décision : défer les deux à v0.6.0.** Selon la règle *refactor conservateur* (pas de churn cosmétique : gain faible × risque non-nul = STOP) — splitter un fichier est medium-risk pour un gain de lecture marginal. Dans une ligne de release contract-preserving (v0.5.x), la valeur risk-adjusted est négative. v0.6.0 est un bump majeur qui perturbe déjà les chemins d'import et est l'endroit naturel pour les shifts structurels.

Le test `#15a` (ajouté en v0.5.0) pin tous les prefixes de clé actuels ; quelle que soit la décision du split en v0.6.0, le test attrape les prefixes non gérés au moment du PR avant qu'ils régressent.

### Diff net

| Fichier | Delta | Notes |
|---|---|---|
| `bob/_tty.py` | +24 | Helper `prompt_wizard()` + réécriture docstring module |
| `bob/cron.py` | +1 | 10 sites `input()` migrés ; net minimal car la signature helper est similaire en lignes au boilerplate inline |
| `bob/checks/updates.py` | +20 | Logique cache APT option C + commentaire in-line extensif |
| `bob/domain_scores.py` | +10 | 3 nouvelles entrées dans `_PREFIX_TO_DOMAIN` + bloc commentaire 6 lignes citant #15b |
| `bob/_paths.py` | +5 | Bump log level + message DEPRECATED + update docstring |
| `bob/locales/{en,fr}.json` | +4 | 2 nouvelles clés × 2 locales |
| `tests/test_domain_scores_mapping_complete.py` | −6 | 3 entrées retirées de `_CATCH_ALL_BY_DESIGN` + justifications simplifiées |

**Net +49 LoC sur 12 fichiers code.** Comme les Phases 2–4, le delta LoC seul sous-vend le gain structurel : `prompt_wizard` retire ~25 lignes de boilerplate par site consommateur (5 sites × 5 lignes = ~25 lignes net du coût signature helper) ; cache APT C est +20 *nouvelle feature* (pas un refactor sauvant des lignes) ; le changement `_PREFIX_TO_DOMAIN` est +10 pour une amélioration sémantique significative.

### Garde-fou diff observable

Audit `sudo python3 -m bob -v -d --french` sur le host dev (so6desktop) à v0.5.4-pre-bump :

- Score global : **8/10** (inchangé depuis baseline v0.5.3 — confirme que le re-bucketing est global-score-neutral).
- Nouveau breakdown score par domaine observé :
  - SSH 10/10 → 7/10 (3 SSH WARNs maintenant correctement attribués au domaine ssh à poids plein)
  - Sécurité Samba 10/10 (nouveau : le domaine Samba surface maintenant avec ses findings OK)
  - Mises à jour 8/10 → 7/10
  - Durcissement 6/10 → 5/10
  - Santé des disques 9/10 → 10/10
  - Pare-feu & Services 3/10 → 10/10 (#15b a déplacé `virt.bypass_risk` et autres entrées catch-all hors firewall)
- Section MISES À JOUR SYSTÈME : INFO cache APT **supprimé** (4 paquets sécurité en attente → WARN sécurité est le signal primaire, INFO C correctement silencé).
- Pas de WARNING `UFW_AUDIT_SHARE` (env var pas set sur le host dev).

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4538 passed in ~6s
```

**4538 → 4538 (inchangé).** Phase 5 est contract-preserving.

### Compatibilité

- **Contrat JSON** : `schema_version="1"`, les 116 EXPLAIN_KEYS, les 34 sections filtrables — **inchangés**.
- **Sortie wire** : 1 nouvelle ligne INFO sur hosts idle avec cache frais-mais-pas-zéro (cache APT C). Reshuffle par-domaine sur hosts émettant `fail2ban.*` / `virt.*` / `docker_audit.*`. **Score global inchangé.**
- **API externe** : aucun breaking change. `prompt_wizard` est un nouveau symbole semi-public dans `bob._tty` ; le `read_line` existant continue de fonctionner comme avant.
- **i18n** : 2 nouvelles clés locale (`updates.apt_cache_age` + `..._detail`) en EN + FR.
- **Contrat plugin** : inchangé. Les auteurs de plugins écrivant des checks custom ne sont impactés par aucun changement Phase 5.

---

## [v0.5.3] — 22-05-2026

**Refactor v0.5.x — Phase 4 sur 5.** Trois findings d'audit : **#5 table de dispatch**, **#12 helpers summary**, **#8 retrait escape hatch `log_data`**. Aucun changement de comportement — 4538/4538 tests inchangés, sortie wire bit-identique à v0.5.2.

### #5 — Table `_LEVEL_DISPATCH` pour `display_result`

`display_result()` dans `bob/display.py` avait une cascade 4-branches OK/WARN/ALERT/INFO. Chaque branche répétait le même pattern (écrire dans le rapport, vérifier le threshold, imprimer le message, optionnellement imprimer récurrence/détail/cmd/note/CIS) avec des variations subtiles par niveau qui avaient dérivé au fil du temps.

Nouvelle dataclass frozen `_LevelTraits` + table 4-lignes exprime chaque variation comme un trait booléen :

```python
@dataclass(frozen=True)
class _LevelTraits:
    report_label:         str
    threshold_key:        str
    print_fn:             Callable[[str], None]
    has_recurrence:       bool
    has_body:             bool
    detail_unconditional: bool   # ALERT uniquement : imprime détail sans --verbose
    show_note:            bool   # ALERT uniquement
    show_cis:             bool   # WARN + ALERT
```

Le trait unique qui capture la spécificité d'ALERT (détail imprimé même sans `--verbose`) est `detail_unconditional=True`, remplaçant un branchement opaque `elif detail: print_recommendation(detail)` qui vivait sous la chaîne `if finding.cmd and verbose:`. `_emit_finding_body()` est un nouveau helper module-level qui consomme les traits.

La table de dispatch est construite à l'intérieur de `display_result()` plutôt qu'au niveau module — `print_ok` / `print_warn` / `print_alert` / `print_info` sont des imports différés (le pattern existant pour éviter la dépendance circulaire `bob.output ↔ bob.display`). La construire par appel a un coût trivial (4 entrées) et préserve la discipline lazy-import.

### #12 — Split `print_audit_summary` en 3 helpers

La fonction `print_audit_summary()` de 142 lignes mélangeait trois responsabilités (lignes header, lignes finding blocks, lignes breakdown) avec une closure interne `_add_finding_lines()`. Désormais :

- `_summary_header_lines(engine, network_context, config, t, profile_name, prev_score)` — lignes score/niveau/réseau/profil/target + la flèche de tendance de score.
- `_summary_findings_lines(engine, t, inner)` — blocs action + improvement (avec la ligne de disclaimer).
- `_summary_breakdown_lines(engine, t, inner)` — déductions + cap_info.
- `_add_finding_lines(icon_prefix, item, inner)` — promu d'inner closure à helper module-level, retourne une liste de tuples `(content, val)` au lieu de muter la liste `lines` englobante.

`print_audit_summary` devient un assembleur 3 lignes `lines.extend(...)`, puis `print_summary_box(lines)`, puis le footer (ligne verdict + implicit_svcs + scope lines + `report.write_summary()`).

Side-fix : le `report.write_summary(score=score, risk_level=level_str, network_context=ctx_str, ...)` original référençait des variables locales qui n'étaient plus dans la portée après l'extraction du header. Remplacé par des expressions directes sur `engine.score` et re-évaluation `t(f"scoring.level.{engine.level.value}")` / `t(f"scoring.context.{network_context}")`. Attrapé par `TestScoreTrend` + `TestDuplicateFindings` + `TestExplainHintAbsent` qui exercent `print_audit_summary` end-to-end (8 failures → 0 après le fix).

### #8 — Escape hatch `CheckResult.log_data` supprimé

`CheckResult` avait un champ `log_data: dict | None = field(default=None)` utilisé uniquement par `bob/checks/logs.py` pour attacher des agrégations structurées (top IPs, top ports, brute hits, svc hits) à afficher par l'orchestrateur. Non typé, mono-usage, et indistinguable du flux normal des findings dans la surface dataclass.

Remplacé par :

- Nouvelle dataclass frozen `LogReportData` dans `bob/checks/logs.py` :
  ```python
  @dataclass(frozen=True)
  class LogReportData:
      log_days:       int
      days_available: int
      total:          int
      brute_hits:     list[BruteforceHit]
      top_ips:        list[tuple[str, int]]
      top_ports:      list[tuple[str, int]]
      svc_hits:       dict[str, int]
  ```
- `check_logs(...)` retourne maintenant `tuple[CheckResult, LogReportData | None]`. `None` quand aucun log file trouvé ou log vide (le result porte toujours un finding info/ok).
- `bob/runner.py:408` unpacke le tuple : `logs_result, logs_report = check_logs(...)`.
- `display_log_results(logs_result, snapshot, log_report, config, t, report)` — `log_report` est maintenant un arg positionnel explicite au lieu d'être lu depuis `logs_result.log_data`.
- Champ `CheckResult.log_data` supprimé de `bob/scoring.py`.

Test churn : 3 tests renommés (`test_log_data_attached` → `test_report_data_attached`, `test_top_ips_in_log_data` → `test_top_ips_in_report_data`, `test_service_hits_in_log_data` → `test_service_hits_in_report_data`) et réécrits pour lire `report_data.total` / `report_data.top_ips` / `report_data.svc_hits` au lieu d'un accès clé-dict. ~20 autres sites de tests dans `tests/test_logs.py` + `tests/test_degraded.py` utilisent `result, _ = check_logs(...)` puisqu'ils ne consultent pas le report data.

Le chemin d'early-exit `if log_report is None: display_result(...)` dans `display_log_results()` préserve le comportement v0.5.2 où un result log vide/manquant fallback sur l'affichage générique des findings — sortie wire inchangée quand aucun log file n'existe.

### Diff net

| Fichier | Delta | Notes |
|---|---|---|
| `bob/display.py` | +23 | `_LevelTraits` + `_emit_finding_body` + 3 helpers summary + `_add_finding_lines` module-level |
| `bob/checks/logs.py` | +19 | dataclass `LogReportData` + retour tuple + update docstring |
| `bob/runner.py` | 0 | 1 ligne migrée à l'unpack tuple |
| `bob/scoring.py` | −1 | champ `log_data` retiré |
| `tests/test_logs.py` + `tests/test_degraded.py` | +3 | unpack tuple + 3 tests renommés |

**Net +40 LoC.** Comme les Phases 2–3, le delta LoC seul sous-vend le gain structurel : la cascade 4-branches du display devient une boucle déclarative unique, la fonction summary de 142 lignes devient un assembleur 3 lignes, et l'escape hatch `dict | None` est remplacé par une dataclass typée frozen.

### #13 / #14 / #15b toujours déférés à Phase 5

ssh.py atteint 1324 LoC à l'entrée v0.5.3, inchangé depuis v0.5.2. cron.py + ré-attribution `_PREFIX_TO_DOMAIN` non touchés en Phase 4. Les trois décisions restent dans la queue pour v0.5.4 avec re-check `wc -l` explicite.

### Garde-fou diff observable

Snapshots `sudo python3 -m bob -v --french -n > /tmp/bob_baseline_v052_stdout.txt` et `sudo python3 -m bob --format=json --french > /tmp/bob_baseline_v052.json` capturés avant l'implémentation Phase 4. Deux diffs intermédiaires effectués : après #5 + #12 puis après #8.

| Diff | Deltas stdout | Deltas JSON |
|---|---|---|
| Post-#5+#12 vs baseline | timestamp (+8 min) + compteurs récurrence (+2 audits) + totaux blocks UFW (+14 sur fenêtre 7 jours) | timestamp uniquement |
| Post-#8 vs baseline | timestamp (+4 h) + ports TCP éphémères VSCode (redémarrage PID entre runs) + totaux blocks UFW (+452) + récurrence (+4) | timestamp + âge rkhunter (39j → 40j) |

Tous les deltas confinés à la dérive d'état (timestamps, accumulation logs, artefacts redémarrage processus, compteurs d'âge). **Zéro changement structurel sur l'audit rendu, l'arbre JSON, ou le breakdown du score.** Score sur le host dev : 8/10 en v0.5.2 et v0.5.3, breakdown identique (-1 pwquality, -1 virt.bypass_risk, -1 ssh.x11_forwarding, -1 ssh.allow_tcp_forwarding, etc.).

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4538 passed in ~6s
```

**4538 → 4538 (inchangé).** Phase 4 est un refactor purement structurel.

### Compatibilité

- **Contrat JSON** : `schema_version="1"`, les 116 EXPLAIN_KEYS, les 34 sections filtrables — **inchangés**.
- **Sortie wire** : bit-identique à v0.5.2.
- **Score par domaine** : inchangé.
- **API externe** : aucun breaking change. `LogReportData` est un nouveau symbole semi-public sur `bob.checks.logs` mais le seul consommateur est `bob.runner` → `bob.display`. Les auteurs de plugins écrivant des checks custom n'étaient jamais censés setter `CheckResult.log_data` — ce champ était de l'espace scratch interne aux logs UFW.
- **i18n** : aucun changement de clé locale.

---

## [v0.5.2] — 22-05-2026

**Refactor v0.5.x — Phase 3 sur 5.** Deux findings d'audit : **#4 table directive SSH** et **#3 extension callbacks `runner._sec`**. Aucun changement de comportement — 4538/4538 tests inchangés, sortie wire bit-identique à v0.5.1.

### #4 — Table déclarative `_BAD_DIRECTIVES` pour sshd_config

**Problème.** `_check_sshd_config` avait ~9 blocs `if` quasi-identiques : lecture directive depuis `cfg.get()`, comparaison contre une enum "mauvaise", émission finding + déduction associée avec points/clé-i18n/level fixes. Le helper Phase 2 `warn_with_deduction` collapsait déjà chaque paire en un seul appel, mais la *cascade de 9 directives* restait 9 blocs impératifs séparés.

**Fix.** Nouvelle table déclarative + dataclass frozen + helper dans `bob/checks/ssh.py` (cf. version EN pour le code source de `_BadDirective`).

Le check de mutual-exclusion dans `__post_init__` attrape les erreurs de programmation à l'instanciation de la classe (le `dataclass` frozen est créé une fois au chargement du module — toute entrée mal formée fait crasher le démarrage, pas le premier audit).

`_apply_bad_directive(rule, cfg, result, _t) -> bool` lit la valeur de la directive via `cfg.get(rule.name, rule.default)`, invoque `rule.is_bad(value)`, et émet le finding+déduction via le helper approprié `warn_with_deduction` / `alert_with_deduction` (API Phase 2).

**Directives migrées (8)** — entrées de la table :

| Directive | `bad_values` / `safe_values` | Level | Points | Notes |
|---|---|---|---|---|
| `PermitEmptyPasswords` | bad: `("yes",)` | alert | 5 | nature="improvement" |
| `X11Forwarding` | bad: `("yes",)` | warn | 1 | |
| `IgnoreRhosts` | bad: `("no",)` | warn | 2 | |
| `HostbasedAuthentication` | bad: `("yes",)` | alert | 3 | nature="improvement" |
| `PermitUserEnvironment` | bad: `("yes",)` | warn | 1 | |
| `StrictModes` | bad: `("no",)` | warn | 2 | |
| `AllowTcpForwarding` | safe: `("no", "local")` | warn | 1 | `"local"` acceptable — utilise le style `safe_values` |
| `PubkeyAuthentication` | bad: `("no",)` | alert | 3 | nature="improvement", detail_key |

`AllowTcpForwarding` est la seule entrée utilisant `safe_values` — l'alternative serait d'énumérer toutes les bad values mais `"no"` et `"local"` sont les valeurs explicitement acceptables selon la doc OpenSSH.

**Sites gardés impératifs (5+ patterns)** — ne fittent pas le style enum :

- **`PermitRootLogin`** : branchement 4-way. `"yes"` → ALERT (-3pts), `"no"` → OK (message spécifique), `"prohibit-password"` ou `"forced-commands-only"` → OK (message différent avec template var `value=`), autre → INFO.
- **`PasswordAuthentication`** : dépend du flag orchestrator-level `ssh_exposed`. Quand SSH est exposé (réseau public ou policy `allow`), WARN + déduction. Quand SSH est LAN-only, downgrade en INFO avec message context-aware.
- **`MaxAuthTries`** : seuil entier (`>3`). Pas un enum ; la template var (`value=N`) est l'entier observé.
- **`LoginGraceTime`** : seuil entier (`>60s`) mais INFO uniquement — pas de déduction.
- **`AllowUsers/AllowGroups`** : détecte l'*absence* de directive de restriction. INFO uniquement.
- **Match block** : INFO quand le parser a détecté des sous-blocs (leur contenu est policy-dépendant et hors scope).
- **Weak Ciphers/MACs/KexAlgorithms** : géré par `_check_weak_algo`. La "mauvaise valeur" est une *intersection de set* entre la liste d'algorithmes configurée et le set d'algorithmes faibles — forme différente que `_BadDirective`.

**Résultat.** Le corps de `_check_sshd_config` passe de ~180 LoC à ~50 LoC (réduction ~70% de la taille de fonction). La table + dataclass + helper ajoutent ~130 LoC en tête de fichier. Net `ssh.py` : +56 LoC.

**Audit-vs-réalité.** L'audit original estimait que #4 économiserait -150 LoC. La réalité est +56 net. L'écart vient de la verbosité Python dataclass.

Le *bénéfice est structurel*, pas LoC-économique : ajouter un nouveau "bad sshd directive" nécessite maintenant d'ajouter 1 entrée à `_BAD_DIRECTIVES`, pas dupliquer un if-bloc. La classe de drift (oublier `nature=` sur une déduction, ou copier-coller un mismatch de `key=` entre finding et déduction) est maintenant structurellement impossible.

---

### #3 — Extension `runner._sec` avec callbacks `skip_if=` et `post_display=`

**Problème.** La closure `_sec(section, snapshot, check_fn, **check_kwargs)` introduite en Phase 1 (v0.5.0) gérait le pattern canonique. Mais 4 sections ne pouvaient pas l'utiliser car elles nécessitaient des extensions orthogonales :

- **Gating conditionnel sur snapshot** : `samba`, `docker_audit`, `desktop_apps` doivent skipper toute la section (pas d'en-tête, pas de check) quand le snapshot reporte que le service sous-jacent n'est pas installé/détecté.
- **Appels d'affichage post-check** : `disk` nécessite un appel `display_disk_partitions(snapshot, t, output)` additionnel après le display standard.

Pre-v0.5.2, ces 4 blocs étaient open-coded inline, chacun ~8 LoC dupliquant le corps de `_sec`.

**Fix.** Deux paramètres callback keyword-only ajoutés à `_sec` (cf. version EN pour la signature détaillée).

Le séparateur `*,` force les deux callbacks à être passés en kwargs — empêche la confusion d'args positionnels aux call sites. Les 16+ call sites `_sec(...)` existants ne sont pas affectés (aucun n'utilisait d'args positionnels après le 3ème).

**Sites migrés (4)** : `samba`, `docker_audit`, `desktop_apps`, `disk`. Net `runner.py` : **−29 LoC**.

**Sites NON migrés** (légitimement complexes) : `services`, `firewall`, `rules`, `ports_analysis` — couplages cross-check, snapshot variables consommées par plusieurs checks suivants.

---

### #13 (split ssh.py) — déféré à Phase 5

La prédiction de l'audit :
> Combiné avec #1, ssh.py descend sous 1000 LoC → #13 (ssh.py split) devient inutile.

Réalité (table) :

| Étape | ssh.py LoC | Delta |
|---|---|---|
| v0.4.8 (avant refactor v0.5.x) | 1387 | — |
| v0.5.0 (Phase 1) | 1387 | 0 |
| v0.5.1 (Phase 2 — #1) | 1268 | −119 |
| v0.5.2 (Phase 3 — #4) | 1324 | +56 |

ssh.py reste à 1324 LoC, 32% au-dessus de la cible 1000. Selon la règle *refactor conservateur*, split de ssh.py est une chirurgie medium-risk. Décision déférée à **Phase 5 (v0.5.4)** avec #14 (split cron.py) et #15b (ré-attribution `_PREFIX_TO_DOMAIN`).

---

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4538 passed in ~6s
```

**4538 → 4538 (inchangé).** #4 et #3 sont des refactors purement structurels.

### Compatibilité

- **Contrat JSON** : `schema_version="1"`, les 116 EXPLAIN_KEYS, les 34 sections filtrables — **inchangés**.
- **Sortie wire** : bit-identique à v0.5.1.
- **Score par domaine** : inchangé.
- **API externe** : aucun breaking change. `_BadDirective` et `_BAD_DIRECTIVES` sont module-private ; l'extension de signature `_sec` est keyword-only.
- **i18n** : aucun changement de clé locale.

---

## [v0.5.1] — 22-05-2026

**Refactor v0.5.x — Phase 2 sur 5.** Le gros gain LoC. Cette release attaque **l'audit finding #1** : l'idiom paired `result.warn(...) + result.add_deduction(...)` se répétant ~130 fois dans `bob/checks/*.py`. Après que Phase 1 (v0.5.0) ait shippé les findings low-risk additifs + la passe couverture cron, Phase 2 collapse le pattern boilerplate dominant.

**Aucun changement de comportement.** Les tests restent à 4538/4538 parce que le helper produit un `Finding` et une `Deduction` par appel, bit-identique à la séquence 2 appels pré-migration.

### Nouvelle API `CheckResult` (additive — pas de breaking change)

Deux méthodes ajoutées à `bob/scoring.py:CheckResult` (après les shorthands `warn`/`alert` existants) :

```python
def warn_with_deduction(
    self,
    key: str,
    *,
    message: str,
    points: int,
    reason: str | None = None,
    context: str = "local",
    detail: str = "",
    nature: str = "improvement",
    cmd: str = "",
    cmd_type: str = "fix",
    note: str = "",
    template_vars: dict | None = None,
) -> None: ...

def alert_with_deduction(self, ...) -> None: ...   # miroir, nature default = "action"
```

**Pourquoi keyword-only après `key`** : forcer `message=`, `points=`, etc. comme arguments keyword empêche la confusion d'args positionnels aux call sites. Le slot positionnel `key` rend le site d'appel lisible comme `result.warn_with_deduction(key="ssh.x11_forwarding", ...)` — la clé étant l'identifiant le plus important.

### Périmètre de migration (120 sites dans 27 fichiers)

La migration a été menée en **6 vagues**, ordonnées par complexité de fichier (plus simple d'abord), avec la suite complète relancée après chaque vague :

#### Vague 1 — fichiers single-site (7 sites)
`backup.py`, `ddns.py`, `logs.py`, `memory.py`, `network_context.py`, `smtp.py`, `suid_audit.py`. Swaps triviaux avec override `reason=` au besoin (`backup.no_backup_reason`, `logs.deduction.brute_force`, `smtp.exposed_reason`, `suid_audit.unexpected_suid_reason`).

#### Vague 2 — fichiers 2-site (16 sites)
`cron_audit.py` (2), `docker_audit.py` (2), `fail2ban.py` (2), `firmware.py` (2), `ipv6.py` (1 sur 2), `kernel_modules.py` (2), `ntp.py` (2), `password_policy.py` (2), `ports.py` (1 sur 2), `secure_boot.py` (2), `systemd_timers.py` (2), `umask.py` (2), `updates.py` (2), `user_accounts.py` (2 sur 2).

#### Vague 3 — fichiers 3-site (15 sites)
`auditd.py` (3), `file_integrity.py` (3), `kernel_hardening.py` (3), `log_rotation.py` (3), `rootkit.py` (3). `ssl_certs.py` (3) volontairement skip — les 3 sites utilisent un compteur cappé `total_deduction`.

#### Vague 4 — fichiers 4-6 sites (29 sites)
`file_perms.py` (1 sur 4), `firewall_stack.py` (4), `firewall.py` (4 sur 6 — pilote), `disk.py` (5), `iptables_nftables.py` (5), `clamav.py` (5), `mac_policy.py` (5 sur 6), `samba.py` (5 sur 6).

#### Vague 5 — `hardening.py` (8 sites)
Toutes les branches de policy sysctl : rp_filter, accept_redirects, tcp_syncookies, accept_source_route, accept_redirects_v6, send_redirects, protected_hardlinks, protected_symlinks. Tous `points=1`, tous `context="local"`, message==reason — le fichier le plus uniforme de la migration.

#### Vague 6 — `ssh.py` (24 sites)
Le plus gros fichier (1387 LoC) et la migration la plus complexe. Couvre toutes les directives sshd_config, les clés hôte, le helper `_check_weak_algo`, le dossier `~/.ssh`, les clés privées (incluant le cas suffix `_reason`), authorized_keys (DSA + RSA faible + duplicates), config client (StrictHostKeyChecking, UserKnownHostsFile, ForwardAgent), et known_hosts (types de clé obsolètes). ssh.py a rétréci de **−146 lignes** (33% de toutes les LoC retirées en vague 6).

### Sites volontairement laissés en 2-appels (13)

La migration a été conservatrice — les sites où l'API helper ne fitte pas ont été laissés tels quels et documentés :

| Pattern | Compte | Fichiers |
|---|---|---|
| Déduction cappée (compteur local `_deductions < CAP`) | 7 | `services_state.py` (1), `ssl_certs.py` (3), `file_perms.py` (2), `ipv6.py` (1) |
| Branching de niveau (warn OU alert sur condition séparée) | 4 | `services.py` (1), `ports.py` (1), `docker.py` (2) |
| Calcul conditionnel `points = 0 or N` | 1 | `docker.py:172-187` |
| `template_vars` différents entre finding et reason | 1 | `firewall.py:_check_open_any` (`rule=clean` pour finding, `rule=""` pour déduction) |

L'override `reason=` du helper gère le cas le plus facile d'asymétrie (clé i18n différente, mêmes template_vars). Des template_vars différents est un pattern plus rare qui ne justifie pas un deuxième paramètre d'override.

### Usage de l'override `reason=`

Sur les 120 migrations, ~85 sites passent un `reason=` explicite parce que le code original utilisait une clé i18n suffixée `_reason` pour la déduction (ex `ssh.host_key_dsa_reason` vs `ssh.host_key_dsa`). Ce pattern a été introduit en début de v0.4.x pour garder les strings de breakdown de déduction concises vs les messages de finding plus longs. Le helper préserve la distinction en acceptant l'override ; le défaut de `reason` à `message` couvre les ~35 sites où le code original avait `_t(KEY)` deux fois.

### Pourquoi la migration n'a pas changé les tests

Chaque appel helper appelle en interne `self.warn(...)` (ou `.alert(...)`) suivi de `self.add_deduction(...)`. Les deux méthodes appendent un `Finding` et une `Deduction` à `result.findings` et `result.deductions` respectivement. Les tests vérifient ces listes via `len()`, accès attribut sur les entrées individuelles, ou `assert_count_per_level()` — aucun ne se préoccupe de savoir si les entrées ont été émises via le helper ou via 2 appels séparés. La sortie wire est identique.

Le seul risque théorique serait si un test patchait `CheckResult.warn` ou `.add_deduction` pour compter les invocations. Un grep a trouvé zéro test ainsi — tous les tests attestent sur les listes `result.findings` / `result.deductions` résultantes.

### Diff stats

```
$ git diff --stat
 37 files changed, 483 insertions(+), 1002 deletions(-)
```

**Net : −519 lignes.** Plus proche de l'estimation "~800 LoC retirés" de l'audit si les 13 sites skip avaient aussi été migrés, mais l'approche conservatrice sur les patterns `_deductions < CAP` et le branching `warn`/`alert` est le bon arbitrage — ces sites nécessiteraient un helper de forme différente et une réécriture de leur logique environnante.

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4538 passed in ~6s
```

**4538 → 4538 (inchangé).** Chacune des 6 vagues a passé `pytest tests/` proprement avant de passer à la suivante. Aucun nouveau test nécessaire (le comportement du helper est pinné par les tests de comptage finding/déduction existants à travers les 33 fichiers de check).

### Compatibilité

- **Contrat JSON** : `schema_version="1"`, les 116 EXPLAIN_KEYS, les 34 sections filtrables — **inchangés**.
- **Surface CLI** : aucun nouveau flag, aucun flag retiré.
- **Score par domaine** : inchangé (même `_PREFIX_TO_DOMAIN`, même mapping de domaine pour chaque clé émise).
- **Sortie wire** : bit-identique à v0.5.0. Messages de findings, raisons de déductions, template_vars, recurrences, refs CIS — tous préservés.
- **API externe** pour les auteurs de plugins : la forme 2-appels (`result.warn(...) + result.add_deduction(...)`) **fonctionne toujours**. Le helper est additif — le code plugin inchangé.
- **i18n** : zéro changement de clé locale (les helpers routent à travers les appels `_t` existants à chaque call site).

### Prochaines phases de v0.5.x

- **v0.5.2 (Phase 3)** : audit findings #4 (table directive SSH — `_check_sshd_config` → déclaratif `_BAD_DIRECTIVES`) + #3 (étendre `runner._sec` avec callbacks `skip_if=` et `post_display=`). Risque medium : touche le plus gros fichier de tests (`test_ssh.py`, 1022 LoC) et le control flow du runner.
- **v0.5.3 (Phase 4)** : #5 (table `display_result` LEVEL_DISPATCH) + #12 (helpers extraits de `print_audit_summary`) + #8 (retirer l'escape hatch `CheckResult.log_data`). Risque medium : changements de layout observables.
- **v0.5.4 (Phase 5)** : #6 (helper `_prompt` wizard cron) + #9 (chemin sunset `UFW_AUDIT_SHARE`) + décisions finales sur #13 (split ssh.py) / #14 (split cron.py) / #15b (ré-attribution `_PREFIX_TO_DOMAIN`).

---

## [v0.5.0] — 21-05-2026

**Refactor v0.5.x — Phase 1 sur 5.** Cette release ouvre la **branche v0.5.x**. C'est le premier épisode d'un refactor en 5 phases mappé depuis un audit sub-agent (general-purpose, dispatché 2026-05-21 avec `DOCUMENTS/SNAPSHOT.md` en briefing principal). L'audit a retourné **15 findings refactor**, classés par value/effort, avec classification de risque explicite.

Principe bottom-up pour les 5 phases : **le comportement du pipeline d'audit ne change pas**. JSON `schema_version="1"`, les 7 domaines de score, les 116 EXPLAIN_KEYS, les 34 sections filtrables, les alias `--explain`, les flags CLI, l'héritage de profils, les clés de locale — tout est stable. Phase 1 fait le tri des findings additifs et low-risk.

### Plan des phases (figé 2026-05-21)

| Phase | Version | Thème | Findings | Risque |
|---|---|---|---|---|
| 1 | **v0.5.0** (cette release) | Quick wins + couverture cron | #7, #2, #10, #11, #15a + tests cron | low |
| 2 | v0.5.1 | Le gros gain LoC | #1 `warn_with_deduction` ~130 sites | low |
| 3 | v0.5.2 | Table directive SSH + extension `_sec` | #4, #3 | medium |
| 4 | v0.5.3 | Refactor display + escape hatch log_data | #5, #12, #8 | medium |
| 5 | v0.5.4 | Wizards cron + sunset UFW_AUDIT_SHARE | #6, #9, possiblement #13/#14/#15b | medium |

#13 et #14 (splits ssh.py / cron.py) sont **conditionnels** — réévalués fin Phase 5. #15b (ré-attribution des fallbacks silencieux) est medium-risk car il change les sorties de scoring — explicitement reporté.

---

### #7 — `is_unit_active()` / `is_unit_enabled()` centralisés

**Problème.** Dans 9 modules check, l'idiom `out = (_run("systemctl", "is-active", X) or "").strip(); if out == "active"` se répétait : `auditd.py`, `fail2ban.py`, `clamav.py`, `ntp.py`, `ddns.py`, `updates.py`, `ssh.py`, `backup.py`, `log_rotation.py`. `backup.py` ajoutait `.lower()` défensif.

**Fix.** Deux helpers publics dans `bob/checks/_run.py` (cf. version EN pour le code). Le `.lower()` défensif est promu au helper — bénéficie aux 9 appelants. **Validé explicitement par l'utilisateur** lors de la review : "peut-être paranoïaque, mais dans le cas peu probable mais existant qu'une distro outpute 'Active\n' ce serait embêtant, et le coût est nul".

`services.py::_detect_single_unit_state` n'est **PAS migré** selon la recommandation de l'audit — sémantique plus riche (templates, state machine active/enabled).

Tests adaptés : `test_fail2ban.py` et `test_ntp.py` patchent maintenant aussi `bob.checks.X.is_unit_active`.

**Monitoring** : `is_unit_enabled` sans consommateur immédiat — gardé pour symétrie d'API, tracé dans `feedback_release_monitoring.md`.

---

### #2 — `bob.output.print_titled_box()` extrait (+ leak `--no-color` corrigé)

**Problème.** Pattern 3-lignes open-coded à 4 sites (cron.py x3, manage_logs.py x1) avec ANSI escapes inline `\033[1;34m` contournant `_c` — **bug UX latent** : `--no-color` n'affectait pas ces 4 boîtes.

**Fix.** Nouveau `print_titled_box(title, width=62)` dans `bob.output`. Passe par `_c.blue_bold/.bold/.reset` — `--no-color` fonctionne désormais. Utilise `_visual_width(title)` au lieu de `len(title)` (plus robuste i18n).

`bob/fixes.py` non migré : forme différente (streaming `╔ ║ ╠`), déjà via `_c`.

**Monitoring** : paramètre `width` exposé mais jamais surchargé — tracé.

---

### #10 — Protocol `bob.report.Report` (PEP 544)

**Problème.** `AuditReport`, `NullReport`, `MarkdownReport` partagent un contrat de méthodes write sans type formel. `MarkdownReport` est duck-typed (pas d'héritage). Annotation `runner.run_checks(report: AuditReport)` imprécise.

**Fix.** Protocol `Report` dans `bob/report.py` avec 12 membres. `runner.run_checks(report: Report)` annote l'abstrait. Pas de `@runtime_checkable` (statique only, zéro overhead). `__enter__/__exit__` exclus (personne n'utilise `with report:`). `write_services_panorama` exclu (unique à Markdown).

---

### #11 — Closures `emit_section()` + `emit_group()` dans `runner.py`

**Problème.** Motif `if not config.quiet: print_section(t(...)); report.write_section(t(...))` répété 20 fois dans `run_checks()`. Surface de drift.

**Fix.** Deux closures en tête de `run_checks()` (pattern identique à `_sec()` existant). 5 `emit_group` (groupes) + 15 `emit_section` (sections) migrés. `_sec()` lui-même dogfoode `emit_section`. **Net runner.py : −28 lignes.**

Sites NON migrés : ligne 373 (`print_section(t("sections.logs"))` orphelin, pas de `report.write_section` matchant — anomalie préexistante, hors scope) et boucle plugin ligne 648 (`plugin.name` brut, pas une clé traduite).

---

### #15a — `tests/test_domain_scores_mapping_complete.py`

**Problème.** Tout préfixe de clé absent de `_PREFIX_TO_DOMAIN` tombe silencieusement dans le catch-all `"firewall"`.

**Fix.** Test AST scan sur `bob/checks/*.py` qui exige chaque préfixe soit dans `_PREFIX_TO_DOMAIN` OU dans `_CATCH_ALL_BY_DESIGN` avec une justification une-ligne. Le whitelist capture l'état v0.4.x (préfixes domaine-firewall légitimes + fallbacks silencieux à revoir Phase 5 #15b : `smtp`, `fail2ban`, `desktop_apps`, `virt`, `docker_audit`, `ddns`, `prerequisites`).

**+4 tests.** Tout nouveau check ajoutant un préfixe sans handling explicite verra le test échouer avec un message actionnable.

---

### Passe de couverture cron (préalable Phase 5)

cron.py a le pire ratio de tests du codebase (SNAPSHOT : 0.60×). Phase 5 refactorera les 3 wizards plain-text (#6) — couverture *avant* refactor = filet de sécurité.

**+35 tests** dans 5 nouvelles classes : `TestValidateCronField` (13), `TestValidateCustomCron` (7), `TestBuildScriptContent` (7), `TestApplyCronSchedule` (3), `TestApplyCronEmail` (5).

Les tests `TestApplyCronEmail` couvrent notamment la **parité regex legacy `NOTIFY_EMAIL=` (sans S)** pour compatibilité wrappers pré-v0.3.

---

### Bug latent corrigé — `_os.open` dans `apply_cron_schedule` (découvert par les nouveaux tests)

`TestApplyCronSchedule::test_replaces_schedule` a remonté immédiatement :
```
E   NameError: name '_os' is not defined
bob/cron.py:855: NameError
```

**Cause.** Extraction v0.4.8 incomplète : `apply_cron_schedule()` appelait `_os.open(...)`, mais `_os` est aliasé localement dans 3 *autres* fonctions de `cron.py` (lignes 649, 931, 1215 — `import os as _os` scopé à la fonction). Au niveau module, seul `os`. Le helper était silencieusement mort depuis v0.4.8 — l'API publique câblée à la TUI curses (non testée automatiquement) ne le révélait qu'à l'exécution interactive.

**Fix.** 3 références sur 2 lignes : `_os` → `os`.

---

### Tests

```
$ python3 -m pytest tests/ -q
.................. 4538 passed in 7.77s
```

`4499 → 4538` (+39) : +4 depuis `test_domain_scores_mapping_complete.py`, +35 depuis les nouvelles classes cron.

### Compatibilité

- **Contrat JSON** : `schema_version="1"`, les 116 EXPLAIN_KEYS, les 34 sections filtrables — **inchangés**.
- **Surface CLI** : aucun flag ajouté/retiré.
- **Score par domaine** : inchangé (aucune modif `_PREFIX_TO_DOMAIN` — #15b reporté).
- **Fichiers de config** : inchangés. **Clés de locale** : inchangées. **Contrat plugin** : inchangé.

---

## [v0.4.8] — 21-05-2026

**Passe d'audit code-quality 4** — réalisée par un sub-agent `general-purpose` dispatché après le reset du quota mensuel org, briefé avec `DOCUMENTS/SNAPSHOT.md` comme cartographie primaire. L'agent a lancé 4 chasses de patterns de bugs distincts (champs dataclass morts, helpers réinventés, timeouts incohérents, code mort post-refactor) et a retourné **4 IMPORTANT + 5 MINOR + 3 SUGGESTION findings**. Tous corrigés dans cette release, bundlés avec 6 améliorations pyproject.toml queueées depuis v0.4.7. 4499/4499 tests passent.

### I4 — fichiers de log `sudo bob -d` appartenaient à root (seul bug observable utilisateur)

**Reproduit** : n'importe quel `sudo bob -d` sur Linux. Le rapport détaillé à `~/.local/share/bob/logs/bob_YYYYMMDD_HHMMSS.log` était créé en mode `0o600` (correct — output confidentiel) mais avec ownership `root:root` parce que le syscall `open()` se passe dans le contexte sudo. L'utilisateur réel invocateur ne pouvait ni lire ni supprimer ses propres rapports après coup. Idem pour le répertoire parent `logs/` à sa première création via `mkdir(parents=True)`.

**Pourquoi ça a survécu 4 audits** : BOB a un pattern chown-back bien établi via `bob.sysinfo::chown_to_sudo_user(path)` — un thin wrapper autour de `os.chown(path, pw_uid, pw_gid)` résolu depuis `$SUDO_USER`, avec un no-op silencieux quand pas sous sudo. Le pattern était correctement appliqué à **7 modules** qui écrivent dans `~/.config/bob/` (`config.py`, `history.py`, `ignore.py`, `compare.py`, `recurrence.py`, `profiles.py`, `registry.py`) — mais jamais branché pour les deux modules qui écrivent dans `~/.local/share/bob/logs/`. L'omission ne se manifeste qu'au runtime via "permission denied" quand l'utilisateur essaie de `cat`/`rm` son rapport.

**Fix** : `bob/report.py::AuditReport.__init__` appelle `chown_to_sudo_user(path)` juste après le `os.open(..., 0o600)`. `bob/manage_logs.py::get_or_prompt_log_dir` appelle `chown_to_sudo_user(d)` après chaque `d.mkdir(parents=True, exist_ok=True)` (4 branches : `--output-dir`, config sauvée, non-interactif, interactif).

Le fix est non-invasif : zéro impact hors sudo (pas de `SUDO_USER` → early return).

### I1-I3 + M4-M5 — champs dataclass morts purgés

Huit champs dataclass populés par `from_system()` (i.e. faisant du vrai travail I/O à chaque audit) mais jamais lus par aucun consumer. Même classe de bug que le fix v0.4.3 C1 qui avait retiré 5 attrs morts de `HardeningSnapshot` causant des crashes `--json-full`.

| Check / dataclass | Champ(s) retiré(s) |
|---|---|
| `SSHSnapshot` | `config_source_files` (populé par walker récursif Include sshd_config ; le paramètre `sources` de `_parse_config_file()` est aussi dropped) |
| `FirewallStatus` | `ipv4_rules_count` + `ipv6_rules_count` (deux counters calculés à chaque audit via `sum(1 for ln in ...)` ; seuls consumers étaient les fixtures de tests) |
| `SambaSnapshot` | `min_protocol` (capturé depuis `min protocol` smb.conf ; seul `smb1_enabled` dérivé est consommé) |
| `ClamAVSnapshot` | `last_scan_log_path` + `db_path` (`_find_last_scan_date()` retournait un tuple mais seul `date` était utilisé ; simplifié pour retourner `Optional[str]`) |
| `SecureBootSnapshot` | `method` (détection method interne, "mokutil"/"efivars"/"bootctl" ; seul `state` est consommé) |

Tests mis à jour pour ne plus passer les kwargs supprimés. `test_default_method_is_none` dans `test_secure_boot.py` retiré (testait juste l'existence du champ). Net : -1 test.

### M1 — cohérence `_C_LOCALE_ENV`

Trois sites subprocess by-passaient la convention `env=_C_LOCALE_ENV` :

| Fichier | Ligne | Commande |
|---|---|---|
| `bob/checks/desktop_apps.py` | 111 | `ps -eo comm` |
| `bob/checks/smtp.py` | 58 | `ps -eo comm` |
| `bob/checks/smtp.py` | 102 | `ss -tlnp` / `netstat -tlnp` |

Aujourd'hui les sorties se trouvent indépendantes de la locale sur toutes les distros ciblées, donc le bypass est bénin. Mais la convention existe pour une raison — un futur `ss` qui localiserait "LISTEN" ou `ps` qui localiserait ses headers casserait silencieusement la détection dans ces checks pendant que tous les autres checks de BOB continueraient de fonctionner. Même leçon v0.4.3 strptime, appliquée préemptivement. Corrigé via `env=_C_LOCALE_ENV` sur les 3 sites.

### M3 — `log_rotation._service_active` inliné via `_run`

La fonction faisait 12 lignes de `subprocess.run(["systemctl", "is-active", name], ...)` + handling d'exception + `.stdout.strip() == "active"`. Le même pattern était déjà implémenté en one-liner via `_run()` dans `clamav.py`, `fail2ban.py`, `auditd.py`, `ssh.py`. Remplacé par `return _run("systemctl", "is-active", name, timeout=5).strip() == "active"`. Les imports locaux `subprocess` et `_C_LOCALE_ENV` devenus inutiles après le nettoyage — aussi retirés.

### M2 + S2 — dédoublonnement gestion cron (avec parité NOTIFY_EMAIL legacy)

`bob/cron.py::edit_cron_schedule` (wizard plain-text) et `bob/tui/cron.py::_apply_cron_schedule` (curses TUI) dupliquaient la même logique atomic-write + regex. Idem pour `edit_cron_email` (plain) vs `_apply_cron_email_str` (curses). La branche curses utilisait `r"^NOTIFY_EMAILS=.*$"` (force la forme S-suffixée moderne), tandis que la branche plain utilisait `r"^NOTIFY_EMAILS?=.*$"` (le `?` rend le S optionnel, supportant les cron files BOB pré-v0.3 qui écrivaient `NOTIFY_EMAIL=` sans le S). Résultat net : les users migrant d'une entrée cron pré-v0.3 pouvaient éditer leur email de notification via le wizard plain mais pas via la TUI curses — inconsistance UX silencieuse.

**Fix** : `apply_cron_schedule(entry, schedule_expr) -> str` et `apply_cron_email(entry, new_email) -> tuple[str, int]` promus en helpers publics dans `bob/cron.py`. `bob/tui/cron.py` les importe et expose des wrappers fins sous les noms `_apply_*` originaux pour les call sites existants (délégation d'une ligne chacun). La regex legacy `NOTIFY_EMAILS?=` est maintenant l'unique source de vérité pour les deux branches.

### S1 — fenêtre auth_log 90 jours documentée comme intentionnelle

`bob/checks/auth_log.py::_read_auth_from_journald` hardcode `max_days: int = 90` pour l'historique d'authentification SSH via `journalctl -t sshd --since=...`. L'audit a flaggé l'asymétrie avec le flag CLI `--log-days` (default 7) qui contrôle l'analyse des logs UFW dans `bob/checks/logs.py`. Investigation : c'est **intentionnel** et les deux fenêtres ont des sémantiques différentes.

Les logs UFW sont bruyants à chaque tentative de connexion — une fenêtre de 7 jours garde la table top-IPs / brute-force lisible et évite d'enterrer les vrais signaux. Les tentatives brute-force SSH peuvent être lentes et sporadiques sur plusieurs semaines ou mois (surtout contre un SSH hardenisé qui auto-ban après N essais — l'attaquant rotate ses IPs). Une fenêtre de 90 jours attrape ce signal long-tail. Documenté dans le docstring de la fonction pour que les audits futurs ne le re-flaggent pas comme inconsistance.

### S3 — `SCORE_BAR_WIDTH` exporté depuis `bob.output`

`_BAR_WIDTH = 10` était dupliqué en constante module-level dans `bob/breakdown.py`, `bob/domain_scores.py`, et `bob/display.py`. Les deux premiers sont des largeurs de barres de score (unité : score, range 0-10) ; le troisième est la largeur de barre disque-pourcent (unité : pourcentage, range 0-100) et est indépendant.

**Fix** : `SCORE_BAR_WIDTH = 10` promu depuis le `_SCORE_BAR_WIDTH` privé déjà utilisé par `output.score_bar()` (introduit dans l'harmonisation des jauges de v0.4.7). `breakdown.py` et `domain_scores.py` font maintenant `from bob.output import SCORE_BAR_WIDTH as _BAR_WIDTH`. `display.py::_BAR_WIDTH` laissé seul — même valeur numérique, unité sémantique différente, coïncidemment égale.

### Hardening pyproject.toml (queué depuis v0.4.7, appliqué ici)

Pendant la prep de v0.4.7 un audit exhaustif du pyproject.toml avait identifié 6 améliorations différées pour éviter de mélanger la plumberie release avec des changements structurels. Toutes appliquées en v0.4.8 plus un bonus :

1. **`Development Status :: 4 - Beta` → `5 - Production/Stable`**. 4499 tests, 7 distros CI, hardware production audité, 17+ releases PyPI depuis v0.1.0, contracts gelés. "Beta" suggérait "may have breaking changes within minor versions" — ce qui n'est plus vrai depuis v0.4.0.

2. **Champs `authors` + `maintainers` ajoutés**. PyPI affichait "Author: UNKNOWN" parce que les metadata PEP 621 n'avaient pas d'info auteur. Maintenant `pyproject.toml` porte l'attribution canonique.

3. **`[project.optional-dependencies] geoip = ["geoip2>=4.0"]`**. La feature de geolocation IP dans `bob/checks/logs.py` fait `try: import geoip2.database` avec fallback silencieux. La dépendance était auparavant installée via `pipx inject bodyguard-of-bits geoip2` — clunky. Maintenant les users peuvent `pipx install "bodyguard-of-bits[geoip]"` en une seule étape.

4. **`wheel` retiré de `build-system.requires`**. Depuis setuptools 70, `setuptools.build_meta` auto-resolve wheel — le lister explicitement est redondant et ralentit légèrement la préparation de l'env de build dans les builds PEP 517 isolés.

5. **URLs `Source` + `Documentation` ajoutées** à `[project.urls]`. PyPI affiche des icônes spéciales pour ces labels d'URL spécifiques.

6. **`dependencies = []` explicite** avec commentaire "Zero runtime deps — preserve at all costs". PEP 621 rend `dependencies` implicite si manquant, mais l'expliciter donne du poids à la policy.

**Bonus** : `[tool.setuptools.packages.find]::include = ["bob", "bob.checks", "bob.tui"]` (liste explicite) remplace le glob `["bob*"]` précédent. La forme glob inclurait n'importe quel futur répertoire top-level `bob_*` dans le wheel (e.g. un `bob_tmp/` accidentel d'une session de debug). L'explicite est plus défensif.

### Tests

4499/4499 passent — net -1 vs les 4500 de v0.4.7. Le test retiré est `tests/test_secure_boot.py::TestSecureBootSnapshot::test_default_method_is_none` qui assertait juste l'existence du champ `SecureBootSnapshot.method` (qui n'existe plus). Aucun test ne dépendait des autres champs dataclass retirés au-delà des kwargs de fixture — ceux-là ont été nettoyés.

---

## [v0.4.7] — 21-05-2026

**Release de maintenance** — passe d'audit cross-documentation, harmonisation cosmétique UI, refonte de la bash completion et automatisation de la création de release. Aucun changement de comportement dans le pipeline d'audit ; 4500/4500 tests inchangés.

### Audit cross-documentation (24 corrections sur 8 fichiers)

Entre v0.4.6 et v0.4.7 un audit exhaustif a rattrapé les claims qui avaient dérivé entre l'état réel du code et les docs user-facing. Aucun n'est un bug de *code* — ce sont des bugs documentaires qui auraient induit les utilisateurs en erreur en lisant les docs pour anticiper le comportement de l'outil.

#### `README.md` + `README_FR.md` (2 × 2 = 4 fixes)

**1. "9 domaines" → "7 domaines de score"** (lignes 7 et 97). Le "9 domaines" était le compte initial v0.1.0 (CHANGELOG mentionne "46 vérifications · 9 domaines" pour v0.1.0). Le moteur de scoring a été refactorisé en v0.2.x pour consolider en 7 domaines de score (`ssh`, `samba`, `file_perms`, `updates`, `hardening`, `disk`, `firewall`), mais les bannières README et le heading section disaient toujours "9 domaines" jusqu'à v0.4.6 — une dérive doc sur 4 versions mineures.

**2. Tableau de profils réécrit**. L'ancien tableau listait un profil `docker` qui **n'existe pas** (le vrai profil est `container` ; un utilisateur tapant `bob --profile=docker` obtiendrait un warning "Profile 'docker' not found — using default (server)") et inversait la relation `desktop` / `workstation`. En réalité, `desktop.conf` est le profil substantif (étend `server`, 11 overrides) et `workstation` est un alias de rétrocompatibilité que le loader réécrit en `desktop` (`bob/profiles.py::load_profile` fait `if name == "workstation": name = "desktop"`). Le fichier `workstation.conf` est shipped en package-data mais n'atteint jamais le loader. Tableau corrigé avec 4 lignes (`server`, `desktop`, `workstation` comme alias, `container`) et relations exactes.

#### `DOCUMENTS/README_TECH.md` + FR (2 × 2 = 4 fixes)

Même dérive "9 domaines" (ligne 12) → "7 domaines de score". Plus une seconde dérive ligne 79 : "17 clés avec sections par profil" → "19 clés". Vérifié en parcourant `bob/locales/en.json::explain.{key}.server.why`. Aussi "À partir de v0.4.6" → "À partir de v0.4.7" dans la section sur le support Python.

#### `DOCUMENTS/README_DEV.md` + FR (2 × 2 = 4 fixes)

Même "17 clés × 3 profils" → "19 clés × 3 profils" (ligne 57). "Le fichier contient ~1500 clés" → "exactement 1401 clés" (ligne 469). Le "~1500" était une approximation vague qui dérivait ; le compte réel est précis et testable : `en.json` et `fr.json` ont tous deux 1401 clés avec parité stricte (enforced par `tests/test_locale_coverage.py::TestLocaleCoverage`).

#### `man/bob.1` (3 fixes)

**1. Références au flag `--list-checks` supprimées** (ligne 270). Le flag est documenté dans le man mais **n'existe pas** dans `bob/cli.py`. Le vrai format pour lister les sections est `bob --check=list`. Un user tapant `bob --list-checks` obtient `Error: Unknown option: '--list-checks'`.

**2. Claim sur `--min-level=info` valeur valide retirée** (ligne 262). Le man listait trois valeurs valides : `info / warn / alert`. Mais `cli.py:388,396` rejette explicitement `info` (seulement `warn` ou `alert` acceptés ; `info` serait un no-op puisque INFO est le plancher implicite).

**3. Liste des valeurs `--format=FMT` complétée** (ligne 99). Le man listait `text / json / markdown`. Le vrai tuple `_VALID_FORMATS` dans `cli.py:458` est `("json", "json-full", "csv", "markdown", "html")` — manquent `json-full`, `csv`, `html`, et `text` n'est **pas** une valeur valide de `--format=` (c'est le mode de sortie par défaut implicite ; `bob --format=text` est rejeté au parse).

#### `man/bob-profile.5` (3 fixes)

**1. Références au flag `--list-profiles` supprimées** (ligne 53). Même classe de bug que `--list-checks` : le man documentait un flag qui n'existe pas.

**2. "Jusqu'à 5 niveaux d'héritage" → "Jusqu'à 8 niveaux"** (ligne 57). La vraie constante est `_MAX_EXTENDS_DEPTH = 8` dans `bob/profiles.py:56`, levant `RecursionError` quand dépassée.

**3. SHIPPED PROFILES enrichi avec l'entrée alias `workstation`**. La section listait 3 profils (`server`, `desktop`, `container`) mais `bob/data/profiles/` contient 4 fichiers. Le man documente maintenant `workstation` comme alias de rétrocompatibilité. La description de `container` a aussi été réécrite pour matcher le vrai `container.conf::[skip_sections]`.

#### `DOCUMENTS/AUTOMATION.md` + FR (4 × 2 = 8 fixes)

La doc webhook contenait quatre erreurs significatives qui auraient conduit les intégrateurs à écrire des receivers cassés.

**1. Structure du sample JSON fausse**. La doc montrait `alerts` et `warnings` comme tableaux d'objets `{key, message}`. Le vrai payload JSON les expose en **entiers (compteurs)** (`engine.alert_count`, `engine.warn_count`). Un receiver implémentant `for alert in payload["alerts"]:` crasherait avec `TypeError: 'int' object is not iterable`. Pour énumérer les findings, le receiver doit appeler BOB avec `--json-full` qui ajoute un tableau `findings` top-level. Le sample corrigé inclut les vrais champs (`version`, `score_max`, `network_context`, `public_ip`, `deductions`, `domain_scores`).

**2. Casse du champ `risk` fausse**. Sample montrait `"risk": "LOW"` (uppercase). Le vrai JSON sérialise `engine.level.value` qui est en lowercase (`"low"` / `"medium"` / `"high"` / `"critical"` — voir `bob/scoring.py:45-50`).

**3. Claim sur la condition de webhook fausse**. La doc disait "Le webhook est POSTé **uniquement si des alertes ou avertissements sont présents**". Le vrai code (`bob/__main__.py`) n'a aucun seuil de count — le webhook est POSTé à chaque audit dès qu'une URL est configurée et que `--offline` n'est pas activé, y compris pour les audits clean. La doc corrigée précise "filtrer côté récepteur en inspectant `alerts`/`warnings`/`score`".

**4. Timeout webhook faux**. Doc disait "timeout de 5 secondes" ; la vraie constante est `_TIMEOUT_SECONDS = 10` dans `bob/webhook.py:39`. La même dérive était présente dans `DOCUMENTS/SNAPSHOT.md` et avait été corrigée là pendant les passes d'audit SNAPSHOT — mais la copie dans AUTOMATION.md n'avait pas été propagée. Exemple type de pourquoi les faits dupliqués dans la doc dérivent.

#### `SECURITY_FR.md` (1 fix)

Le header `## Threat model` était resté en anglais quand le fichier a été forké en français. Le contenu du body était déjà traduit ; seul le heading avait été oublié. Corrigé en `## Modèle de menace`.

### `DOCUMENTS/SNAPSHOT.md` — nouvelle cartographie interne

Un nouveau document interne de ~640 lignes a été créé dans `DOCUMENTS/` pour fournir une vue d'ensemble single-page du codebase. Le but est double :

1. **Préparation de refactor** : avant une refactorisation non-triviale, le maintainer n'a plus besoin de re-découvrir la structure, le graphe de dépendances et les contracts gelés module par module.

2. **Briefing sub-agent** : quand on délègue une tâche d'audit profond ou de refactor à un sub-agent, passer SNAPSHOT.md comme premier item de contexte réduit drastiquement l'exploration que l'agent doit faire.

**Contenu** : diagramme ASCII d'architecture · arbre annoté · index des modules `bob/` racine (38 modules) et `bob/checks/` (43 checks) avec LoC et rôles · graphe de dépendances (centralité in/out-degree) · hotspots et ratios tests-to-code · 6 patterns/conventions avec exemples · 7 contracts gelés · surface CLI (~40 long + 21 short) · paths fichiers & env vars · mapping tests-to-source · décisions architecturales · matrice CI · "Chiffres clés".

**Validation** : le document a subi **20 passes successives de correction** contre l'état réel du code, produisant 46 corrections au total. Bugs notables rattrapés : `~18 kLoC` headline → `~28 kLoC` (auto-incohérence entre header et footer qui a survécu 19 passes précédentes) ; le diagramme ASCII montrait `runner.py → domain_scores.py` mais `runner.py` n'importe pas `domain_scores` (vérifié par scan AST) ; description `--show-ignored` fausse ; `--ignore=KEY` listé en Filter alors qu'il s'agit d'une opération Setup qui exit immédiatement ; env var `NO_COLOR` listé comme honoré alors qu'aucun chemin de code ne le lit ; type du champ `network_context` change entre `--json` et `--json-full` ; exemple ScoreEngine manquait le paramètre requis `reason` ; paths cron utilisaient `{name}` mais les vrais paths utilisent `{slug}` dérivé via `make_slug()` ; "5s timeout" → 10s (même correction que AUTOMATION.md) ; "5 compound-risk rules" → 6 ; signature de pattern ne matchait pas le style majoritaire ; claim sur le storage des références CIS était trompeur.

Le document est 100% anglais (une passe Franglais a rattrapé 4 expressions françaises résiduelles). Il est interne (pas shipped dans `debian/bob-core.docs` ni `bob.spec %doc`) parce que l'audience est le maintainer et les sub-agents, pas les utilisateurs finaux.

### Harmonisation cosmétique des jauges

Toutes les barres de progression basées sur le score dans l'UI terminale partagent maintenant un schéma de couleur unique via un nouveau helper `bob.output.score_bar(score: int) -> str`. La logique de couleur miroite `display._disk_bar` mais avec des seuils inversés — pour les scores, **haut = bon** :

| Plage de score | Couleur | Sémantique |
|---|---|---|
| ≥ 8 / 10 | vert | sain |
| 5 – 7 / 10 | jaune | modéré |
| 0 – 4 / 10 | rouge | critique |

Avant ce changement, quatre emplacements rendaient les barres en `█ * filled + ░ * empty` brut monochrome — visuellement plat, sans information de gravité conveyée par la couleur. Les barres des partitions disques dans `display.py::_disk_bar` étaient déjà colorées (avec les mêmes seuils appliqués au *pourcentage d'utilisation*, où haut = mauvais — d'où la sémantique inversée). Le nouveau helper aligne le reste de l'UI sur ce style établi.

Renderers affectés (délégation d'une ligne chacun) :

- `bob/watch.py::_score_bar` — l'affichage live du mode `--watch`.
- `bob/breakdown.py::_bar` — le chemin de calcul du score `--breakdown`.
- `bob/domain_scores.py::render_domain_scores` — les barres de sous-scores par domaine dans le résumé d'audit.
- `bob/manage_logs.py` (rendu d'historique à la ligne 69) — la sparkline des scores passés dans le TUI `--manage-logs`.

Le flag `--no-color` / `-n` continue de neutraliser les couleurs.

### Refonte complète de la bash completion (`bob/data/bob.bash-completion`)

#### Bug critique : complétion de valeur `--xxx=<TAB>` échouait silencieusement

L'amélioration la plus visible pour l'utilisateur est la correction d'un échec silencieux long-standing dans la complétion de valeurs. Taper `bob --check=<TAB>` (ou n'importe lequel de `--skip=`, `--min-level=`, `--format=`, `--profile=`, `--lang=`, `--target=`, `--webhook-format=`, `--output=`) ne montrait aucune suggestion.

La cause racine est la façon dont bash split la ligne de commande en mots pour la completion. Avec `COMP_WORDBREAKS` par défaut contenant `=`, taper `bob --check=` et appuyer TAB fait que bash split la ligne en `["bob", "--check", "="]` avec `COMP_CWORD=2` pointant sur le `=` lui-même. La fonction de completion lisait `${COMP_WORDS[COMP_CWORD]}` pour le mot courant — retournant `"="` au lieu de la chaîne vide. Le `compgen -W "${section_list}" -- "="` subséquent ne matchait rien.

Le fix est d'utiliser la convention par arguments positionnels de la lib bash-completion : quand bash invoque une fonction de completion, il passe trois arguments positionnels — `$1` est le nom de la commande, `$2` est le mot courant **propre** stripé de tout préfixe de word-break `=`, et `$3` est le mot précédent. Lire `$2`/`$3` au lieu de `${COMP_WORDS[COMP_CWORD]}`/`${COMP_WORDS[COMP_CWORD-1]}` évite complètement le cas du split `=`.

Le bug a été diagnostiqué en ajoutant un wrapper de debug autour de la fonction dans la session bash interactive de l'utilisateur (Bash 5.2.21), traçant la sortie `set -x` pour chaque pression TAB. Le diagnostic a révélé `words=[bob --check =] cword=2 cur=[=]` après avoir tapé `bob --check=<TAB>` — confirmant l'exposition COMP_WORDS du split brut contre le `$2=""` propre passé via les args positionnels.

Ce bug était présent depuis la release initiale v0.1.0 et a survécu à tous les audits subséquents parce que l'approche de test manuel (mettant `COMP_WORDS=(bob "--check" "=" "")` avec `COMP_CWORD=3`) produisait une forme de word-array différente du vrai bash interactif.

#### Autres corrections

- **Renommage de fonction** : `_ufw_audit` → `_bob`. Le nom de fonction legacy datait d'avant le rename du projet en "Bodyguard Of Bits".
- **Code mort supprimé** : `_ufw_audit_install()` + `complete -F install.sh` enregistraient une completion pour un script `install.sh` qui n'existe plus.
- **Liste des sections factorisée dans `_SECTIONS`**, matchant `bob --check=list` exactement. Suppression de `firewall` (check core, non filtrable). Ajout de `iptables_nft`, `samba`, `desktop_apps` (ajoutés à `_ALL_SECTIONS` entre v0.3.x et v0.4.x mais jamais propagés à la liste de completion).
- **Parité des long-options avec `cli.py`** : ajout de `--check=`, `--skip=`, `--output-dir=`, `--breakdown`, `--no-colour`. Short-options gagne `-B`. Total : 21 short, ~40 long options.
- **Nouveau handler de valeur `--skip=`** (symétrique avec `--check=` minus la valeur spéciale `list`).
- **Tous les handlers de valeur supportent les deux formes** `--xxx=value<TAB>` et `--xxx value<TAB>`.

### CI — release GitHub automatique au push de tag (`.github/workflows/publish.yml`)

Le workflow de publish gagne un 4e job `github-release` qui tourne après le succès du publish PyPI. Le pipeline complet est maintenant :

```
git push --tags
  ↓
test       (matrice Python 3.10/3.11/3.12/3.13)
  ↓
build      (sdist + wheel, uploadés en artifact)
  ↓
publish    (PyPI via Trusted Publishing OIDC)
  ↓
github-release  ← NOUVEAU
  • Extrait le titre depuis la ligne table de CHANGELOG.md
  • Extrait le body depuis la section DOCUMENTS/CHANGELOG_FULL.md
    entre "## [vX.Y.Z]" et le prochain header "## [v" (via awk)
  • Crée la release via softprops/action-gh-release@v2
  • Attache wheel + sdist comme assets de release
  • Marque comme latest
```

Sécurités : `needs: publish` (release uniquement si PyPI réussit), check explicite que la section CHANGELOG_FULL existe (échoue avec `::error::` sinon), permission limitée à `contents: write`.

Avant cette automatisation, les releases GitHub étaient créées manuellement après chaque publish PyPI.

### Tests

Aucun nouveau test ajouté. 3 tests dans `tests/test_breakdown.py::TestBar` adaptés pour stripper les séquences d'échappement ANSI avant d'asserter le contenu visible de la barre (les barres sont maintenant des strings ANSI-colorés au lieu de `█░░░░░░░░░` brut). 4500/4500 tests passent toujours.

---

## [v0.4.6] — 17-05-2026

**La passe terrain v0.4.5 a fait remonter deux bugs reproductibles.** Les deux sont maintenant corrigés. Périmètre strictement limité — hotfix ciblé, aucun changement de comportement en dehors des deux scénarios rapportés.

### Contexte de validation : la passe terrain v0.4.5

Avant d'ouvrir v0.4.6, 13 audits ont été exécutés sur 6 systèmes distincts en utilisant la release v0.4.5 publiée sur PyPI :

| Système | Audits | Verdict |
|---|---|---|
| Mint dev (host) | 1 | propre |
| Debian 13 VM | 3 (pré + `apt upgrade` + `dist-upgrade`) | Bug 2 manifesté après remédiation |
| Kali Rolling VM | 1 | propre |
| Mint test VM | 3 (pré + `apt upgrade` + `dist-upgrade` + `autoremove`) | Bug 1 manifesté après autoremove |
| Ubuntu 26.04 LTS VM | 1 | propre |
| so6desktop production (Linux Mint 22.3) | 2 (pré + post `dist-upgrade` + `autoremove`) | Bug 1 manifesté en production |

Deux bugs reproduits. Le Bug 1 s'est manifesté sur du matériel de production — confirme que ce n'est pas un artefact VM mais le résultat routinier de tout utilisateur nettoyant une image noyau obsolète. Le Bug 2 était lié à une transition spécifique (`WARN/ALERT → OK only` dans un domaine) — périmètre plus étroit qu'initialement supposé, mais une vraie régression d'ergonomie sur le chemin de remédiation.

### Bug 1 — Le listing noyaux ne filtrait pas sur l'état `ii` (installé)

**Déclencheur** : `apt remove linux-image-X` (ou sa forme transitive via `apt dist-upgrade` / `autoremove`) laisse le paquet en état `rc`. `rc` signifie "supprimé, config-files restants" : le binaire noyau dans `/boot` a disparu (`/etc/kernel/postrm.d/initramfs-tools` s'exécute et supprime `initrd.img-X`), mais l'entrée du paquet reste dans la base dpkg avec ses fichiers de config dans `/etc`. Le paquet ne disparaît complètement que si `apt purge` est utilisé ou `dpkg --remove --purge` est exécuté.

**Ce que BOB faisait** : dans `bob/checks/kernel_modules.py`, la construction du snapshot appelait

```python
dpkg_out = _run("dpkg-query", "-f", "${Package}\n", "-W", "linux-image-[0-9]*", timeout=10)
```

Ce format imprime le nom du paquet sans considération d'état. `_parse_installed_kernels` supposait ensuite que chaque ligne retournée était un noyau installé et les listait toutes.

**Ce que l'utilisateur voyait** : la sortie BOB listait des noyaux qu'`apt` avait déjà supprimés. Exemple concret sur so6desktop après `apt dist-upgrade` (qui a supprimé `linux-image-6.17.0-20-generic`) + `apt autoremove` (qui a supprimé `linux-hwe-6.17-headers-6.17.0-20`) :

```
→ Installés  : 6.17.0-19-generic, 6.17.0-20-generic, 6.17.0-22-generic, 6.17.0-23-generic (*)
→ Obsolètes  : 6.17.0-19-generic
→ sudo apt purge linux-image-6.17.0-19-generic
```

`6.17.0-20-generic` avait déjà disparu — son entrée dpkg était `rc`, pas `ii`. Le compteur "Obsolètes" était sous-évalué par effet de bord (1 listé au lieu de 2). La suggestion de purge ciblait le bon noyau, mais le reste du listing était faux.

**Correctif** : dpkg-query est maintenant invoqué avec l'abréviation de statut incluse.

```python
dpkg_out = _run(
    "dpkg-query", "-f", "${db:Status-Abbrev}|${Package}\n",
    "-W", "linux-image-[0-9]*",
    timeout=10,
)
```

`${db:Status-Abbrev}` est une abréviation 2-caractères de `action désirée + état actuel` :

| Code | Désiré | Actuel | Signifie | Action BOB |
|------|--------|--------|----------|------------|
| `ii` | install | installé | paquet installé normal | garde |
| `hi` | hold | installé | installé mais sur apt-mark hold | garde |
| `rc` | remove | config-files | supprimé par `apt remove`, binaires /boot partis | **exclut** |
| `pn` | purge | non-installé | programmé pour purge, jamais réinstallé | exclut |
| `un` | unknown | non-installé | dpkg connaît le nom mais rien d'autre | exclut |
| `iU` | install | unpacked | en cours d'installation, binaires peut-être pas exécutables | exclut |
| `iF` | install | half-configured | transitoire en cours d'installation | exclut |
| `iW` | install | triggers-awaited | transitoire | exclut |

`_parse_installed_kernels` ne garde maintenant que les lignes dont le 2e caractère est `i` — le 2e char encode l'état actuel (n=non-installé, c=config-files, H=half-installed, U=unpacked, F=half-configured, W=triggers-awaited, i=installé). Toute ligne où les binaires sont *garantis* présents passe ; tout ce qui est transitoire ou supprimé est filtré.

**Rétro-compatibilité** : le parser accepte toujours les lignes plain `linux-image-…` sans préfixe `|`. C'est préservé pour deux raisons : (1) les fixtures de tests dans `TestParseInstalledKernels` utilisent le format legacy ; (2) tout chemin de code ou futur appelant qui produit juste le nom du paquet (ex. un fallback si `${db:Status-Abbrev}` est indisponible) continue de fonctionner.

### Bug 2 — Le score baissait après remédiation

**Déclencheur** : un domaine transite de "a au moins un WARN/ALERT" à "émet uniquement des findings OK". Le scénario de référence est `updates` : pré-remédiation un WARN `updates.security_pending` existe, l'utilisateur exécute `apt upgrade`, le run BOB suivant ne voit plus que `updates.ok`.

**Ce que BOB faisait** : `bob/domain_scores.py::active_domains_from_engine()` collectait les domaines pour inclusion dans la moyenne de score globale. Il appliquait un filtre `_actionable = (FindingLevel.WARN, FindingLevel.ALERT)` — un domaine entrait dans le set actif uniquement s'il avait au moins un finding WARN ou ALERT (ou une déduction avec une clé, ce qui est impliqué par WARN/ALERT en pratique).

**Ce que l'utilisateur voyait** : sur Debian 13 VM avec une mise à jour de sécurité en attente :

- **Audit avant `apt upgrade`** — WARN `updates.security_pending` actif → domaine `updates` dans le set actif à 8/10. Autres domaines actifs : `ssh`, `hardening`, etc. Global = moyenne ≈ 7/10.
- **`apt upgrade`** résout la mise à jour de sécurité.
- **Audit après `apt upgrade`** — le check `updates` émet maintenant `updates.ok` et rien d'autre. Le filtre rejette `updates` du set actif. `ssh`, `hardening`, etc. encore présents. La moyenne globale est maintenant sur `N-1` domaines. Maths : retirer un domaine qui avait 8/10 d'une moyenne où plusieurs domaines restants sont en-dessous de 8/10 → moyenne *augmente*. Mais retirer un domaine qui avait 8/10 quand plusieurs domaines restants sont à 4–6/10 fait baisser la nouvelle moyenne. Sur Debian 13 la nouvelle moyenne a baissé de 7 à 6.

L'effet observable utilisateur : faire la bonne chose (appliquer les patches de sécurité) faisait baisser le score. Anti-incitatif sur un outil de hardening.

**Pourquoi le filtre existait** : probablement pour cacher les domaines où aucun service n'est installé (ex. Samba non installé → pas de findings `samba.*` → domaine absent de l'affichage). Cet objectif est légitime. L'implémentation confondait "pas de finding actionnable" avec "pas de signal du tout" et produisait le mauvais comportement à la transition WARN→OK.

**Correctif** : le filtre est maintenant `_actionable = (FindingLevel.OK, FindingLevel.WARN, FindingLevel.ALERT)`. Un domaine est considéré actif quand *n'importe quel* check de ce domaine émet un signal de santé reconnaissable. Les domaines INFO-only restent cachés — la terrain Mint test (seul `updates.regular_pending` INFO présent, pas de WARN, pas de OK) a confirmé que le bug ne s'y manifeste pas, donc la ligne conservatrice est d'exclure INFO de la promotion.

La sémantique correspond maintenant à ce que le docstring affirmait déjà ("Used to hide domains whose service is not installed") — service non installé signifie pas de findings émis, ce qui garde le domaine absent.

**Comportement de score avec le correctif** :

```
Avant remédiation : avg(updates=8, hardening=4, …) / N          = 7
Après remédiation : avg(updates=10, hardening=4, …) / N         = ~7+    ← CORRECT
```

Les domaines avec uniquement des findings OK contribuent maintenant leur score 10/10 propre à la moyenne globale, ce qui est mathématiquement le bon résultat : un domaine qui audite propre devrait tirer la moyenne vers le haut, pas être silencieusement retiré.

**Effets en cascade** à connaître :

- Les domaines où le check pertinent émet toujours un OK (parce que le service est universellement présent et clean sur le système) seront désormais toujours dans le set actif. Sur Ubuntu 26.04 LTS, où beaucoup de checks émettent du pur OK, le dénominateur de la moyenne globale grossit. C'est intentionnel — ces domaines étaient toujours "audités" mais invisibles au score.
- Affichage des scores par domaine : `render_domain_scores` filtre par `active_domains`, donc des domaines 10/10 précédemment cachés peuvent maintenant apparaître. Le breakdown devient plus honnête sur quels domaines ont contribué.

### Tests

**`tests/test_kernel_modules.py`** — nouveaux tests dans `TestParseInstalledKernels` :

- `test_status_prefixed_ii_kept` — les lignes `ii ` basiques produisent la liste de versions.
- `test_status_prefixed_rc_excluded` — reproduction directe du Bug 1 : une ligne `rc ` pour `6.8.0-52` est exclue tandis qu'une ligne sœur `ii ` pour `6.8.0-55` est gardée.
- `test_status_prefixed_excludes_all_non_installed_states` — `ii`, `rc`, `pn`, `un`, `iU` cohabitent ; seul `ii` survit.
- `test_status_prefixed_hi_kept` — les paquets en hold restent dans la liste (les binaires sont encore sur disque).
- `test_mixed_legacy_and_status_prefixed_format` — rétro-compatibilité : une sortie dpkg unique mélangeant lignes préfixées et non-préfixées parse correctement.

**`tests/test_domain_scores.py`** — nouvelle classe `TestActiveDomainsIncludesOK` :

- `test_ok_finding_makes_domain_active` — assertion directe du nouveau comportement de filtre.
- `test_warn_finding_makes_domain_active` — ancien comportement préservé.
- `test_alert_finding_makes_domain_active` — ancien comportement préservé.
- `test_info_only_finding_does_not_promote_domain` — garde-fou de l'exclusion INFO ; si ce test échoue, les domaines INFO-only ont commencé à fuiter dans le set actif.
- `test_no_findings_no_active_domains` — moteur vide retourne toujours un set actif vide ; baseline regression guard.
- `test_remediation_keeps_domain_at_max_score` — reproduction directe Debian 13 sous forme de test : ssh a un WARN (8/10), updates remédié à OK seulement. Asserte que `compute_global_from_domains` retourne `(8+10)/2 = 9` au lieu de `8`.

### Compte de tests

4500 passés (+11 vs v0.4.5). Aucune régression sur le reste de la suite.

### Ce qui NE change PAS

- Le JSON schema reste version 1. Aucun nouveau champ, aucun champ supprimé, aucun champ renommé.
- `EXPLAIN_KEYS` inchangé.
- Aucune nouvelle clé de locale ; aucune clé supprimée.
- API Python publique de `bob.domain_scores` inchangée (signature de `active_domains_from_engine`, type de retour, aucun nouvel argument).
- API Python publique de `bob.checks.kernel_modules` inchangée (signature de `_parse_installed_kernels`, type de retour — elle a toujours pris une string et retourné `List[str]`, et le sens de la string est upward-compatible).
- Aucune nouvelle dépendance (toujours 0 dépendance runtime hors stdlib).

### Hors périmètre (différé)

- **Audit hardening complet par sub-agent** : demandé en parallèle de v0.4.6, différé car la tentative précédente a hit le cap mensuel d'usage de l'org avant de produire un rapport. Voir `[[audit-hardening-en-attente-v0-4-5]]` dans la mémoire agent — à relancer en prochaine session une fois le quota reset.

---

## [v0.4.5] — 16-05-2026

**Release de hardening de l'infrastructure de tests.** v0.4.4 a ajouté `tests/test_locale_coverage.py` pour attraper la classe de régression `logs.attempts` — clés retirées des fichiers de locale alors qu'elles sont encore référencées dans le code. L'implémentation fonctionnait et avait déjà été étendue en v0.4.4 avec trois fixes issus d'une review ChatGPT (negative lookbehind resserré, couverture exhaustive `explain.*`, parité des placeholders). Mais la machinerie sous-jacente reposait encore sur un scan regex des fichiers source, avec des limites documentées : faux positifs dans docstrings, fragilité des call sites multilignes, edge cases d'appels d'attributs. v0.4.5 remplace le pipeline regex par un vrai parsing AST.

### Pourquoi ça compte

Le test attrape une vraie classe récurrente de bug — fallbacks silencieux de locale qui n'apparaissent qu'au test terrain (la sentinelle v0.4.3 `[logs.attempts]` a été découverte post-tag, pas par la CI). Tout l'intérêt d'automatiser ça est pour que la CI attrape la régression avant le tag. Si l'automation elle-même a des angles morts cachés, le filet de sécurité fuit.

Trois problèmes structurels avec le scan regex du code source Python :

1. **Les matches dans docstrings sont des faux positifs qui ressemblent à des vrais.** `bob/i18n.py` documente l'API `t()` avec des exemples comme `t("samba.open_world")` et `t("log.blocked_attempts", count=42)`. Le regex matchait ces exemples comme s'ils étaient de vrais sites d'appel, forçant v0.4.4 à maintenir une allowlist `_KEY_EXCLUSIONS` avec deux entrées. Chaque futur exemple de doc d'API aurait fait grossir cette liste — c'est l'anti-pattern classique "l'allowlist mange les bugs".
2. **Les call sites multilignes sont dépendants du formatage.** Un appel écrit `_t(\n    "foo.bar",\n    x=1,\n)` est sémantiquement identique à `_t("foo.bar", x=1)` mais le regex nécessite que la parenthèse ouvrante et le guillemet ouvrant soient proches. Le regex v0.4.4 gérait la plupart des layouts mais le contrat était implicite et fragile.
3. **Les appels d'attribut passent à travers certains lookbehinds.** v0.4.4 a resserré le negative lookbehind de `[A-Za-z0-9_]` à `[A-Za-z0-9_.]` pour rejeter `obj._t(...)`. Ça couvrait le cas commun, mais la règle était rétroactive — chaque nouvel edge case (identifiants unicode, backslashes de continuation) demanderait un autre tweak du lookbehind.

### Comment l'AST règle les trois

```python
def _is_translation_call(node: ast.Call) -> bool:
    return (
        isinstance(node.func, ast.Name)
        and node.func.id in _TRANSLATION_FUNC_NAMES
    )
```

`ast.parse(source)` retourne l'arbre syntaxique Python. Trois propriétés structurelles résolvent les trois problèmes :

- **Les docstrings sont inertes.** Elles apparaissent comme `ast.Constant(str)` directement dans un body de fonction/classe/module — pas dans un `ast.Call`. Le walker ne les voit jamais.
- **Le whitespace est transparent.** Le même node `ast.Call` représente chaque variante de formatage. Multilignes, single-line, virgule trainante — tous identiques.
- **L'accès attribut est un type de node différent.** `obj._t(...)` produit `ast.Call(func=ast.Attribute(...))`. Le check `isinstance(node.func, ast.Name)` l'élimine par construction. Pas de tweaks de lookbehind, pas de maintenance de liste négative.

L'allowlist `_KEY_EXCLUSIONS` est complètement supprimée. Il n'y a pas de chemin futur où elle grossit.

### Ce qui est préservé

Le contrat externe des tests est identique. Les mêmes 9 tests dans trois classes :

- `TestLocaleCoverage` (5 tests) : scan corpus, résolution EN, résolution FR, parité EN/FR, baseline sanity.
- `TestExplainNamespaceCoverage` (3 tests) : couverture exhaustive `explain.<clé>.{title,why,how}` générée depuis `EXPLAIN_KEYS` figée.
- `TestPlaceholderParity` (1 test) : les placeholders `{nom}` matchent entre en.json et fr.json.

Mêmes fixtures (`en_data`, `fr_data`, `static_keys`, `explain_leaves`), mêmes assertions. Seuls `_all_t_keys()` et deux petites fonctions helper (`_is_translation_call`, `_literal_key_arg`) ont changé.

### Performance

Le parsing AST est plus lent que le regex : 0,32 s vs 0,06 s pour ce fichier de test (~5× plus lent). En absolu négligeable — la suite de tests complète termine toujours en 6,5 s. Aucune optimisation nécessaire.

### Ce que cette release ne change pas

Cette release modifie **uniquement** `tests/test_locale_coverage.py`. Aucun fichier source dans `bob/` n'est touché. Aucun comportement runtime n'est altéré. Le compteur de tests reste à 4489. La forme regex v0.4.4 et la forme AST v0.4.5 retournent le même ensemble de clés sur le codebase actuel — vérifié en lançant les deux contre `bob/`. Le refactor est préventif, pas correctif.

### Tests

4489/4489 — inchangé vs v0.4.4. Les 9 tests dans `tests/test_locale_coverage.py` passent tous sur la nouvelle implémentation AST sans aucune modification de leurs assertions.

### Reporté à une release ultérieure

Cette release ne change pas les items existants de la roadmap :

- Phase 2 Option A — migration systématique `Finding.template_vars` sur les ~37 checks non-pilotes. Toujours en piste pour v0.5.0+. `tests/test_template_vars_migration.py` continue à exposer la dette.
- Matrice CI multi-distros (Debian/Ubuntu/Mint/Kali en conteneurs) et PKGBUILD AUR — contribution communautaire bienvenue.
- Cleanup cosmétique M3 (`os.path` → `pathlib` dans 4 fichiers).

---

## [v0.4.4] — 15-05-2026

**Release de hardening terrain cross-distro.** Quatre nouveaux tests sur VM (Debian 13, Kali Rolling, Linux Mint 22.3, Ubuntu 26.04 LTS — toutes installées depuis PyPI via `pipx upgrade bodyguard-of-bits`) ont fait remonter un bug critique, trois régressions cosmétiques mineures, et confirmé en production que les fixes v0.4.3 fonctionnent. Tous les résultats plus les items reportés de la passe d'audit v0.4.3 (S4 redesign symlink, M4 refactor ports, I2 vague 2 `key=`, test couverture locale) sont groupés dans cette release.

### Le bug critique — et pourquoi il compte

`bob/checks/updates.py` rapportait "système à jour" sur **chaque installation fraîche Debian-family qu'on a testée**. Sur Ubuntu 26.04 LTS spécifiquement, cela signifiait **21 mises à jour officielles de sécurité LTS passées en silence**. Pour un outil d'audit hardening, c'est la pire classe de bug — un faux-négatif sur un check critique de sécurité qui ruine la confiance dans la totalité de la sortie.

Deux causes combinées :

1. **La commande `apt-get -s upgrade` sur laquelle BOB s'appuyait est conservatrice.** Elle refuse d'upgrader tout paquet qui exigerait d'installer un nouveau paquet ou d'en retirer un autre. Sur Debian/Ubuntu, chaque transition de noyau (`linux-image-amd64 → linux-image-6.12.86-amd64`) et chaque bump de soname déclenche exactement ce cas — toute la fermeture transitive est mise de côté. Les utilisateurs réels lancent routinièrement `apt full-upgrade` / `apt dist-upgrade` précisément pour cette raison. BOB simulait un workflow que personne n'utilise réellement.

2. **Le cache APT vit dans `/var/cache/apt/pkgcache.bin` et ne se rafraîchit que quand `apt update` tourne.** Sur les installations vierges (typique des VMs de test, mais aussi de tout utilisateur qui dépend des rafraîchissements `unattended-upgrades` qui peuvent avoir échoué), le cache a des jours ou des semaines. BOB lisait cet état périmé et rapportait "0 en attente" sans aucune réserve.

Le fix superpose trois changements dans `bob/checks/updates.py` :

- **`apt-get -s upgrade` → `apt-get -s dist-upgrade`** dans `_collect_pending_updates()`. Aligne la simulation avec ce que les utilisateurs lancent réellement. La détection des mises à jour de sécurité (via le suffixe `-security` sur la suite source) est inchangée — `dist-upgrade` produit les mêmes lignes `Inst`, simplement plus.
- **Check de fraîcheur du cache.** Nouveau champ `apt_cache_age_days: int | None` sur `UpdatesSnapshot`, peuplé en stat-ant le mtime de `/var/cache/apt/pkgcache.bin`. Quand le cache a plus de 7 jours, le check émet un nouveau WARN `updates.apt_cache_stale` avec une recommandation `sudo apt update`. Le seuil mirrore les fenêtres typiques de rafraîchissement `unattended-upgrades`.
- **Cross-check vs `apt list --upgradable`.** Nouveau champ `upgradable_count: int | None`, peuplé en parsant la sortie d'`apt list --upgradable` (comptage des lignes `pkg/suite ... [upgradable from: ...]`). Quand la simulation `dist-upgrade` rapporte 0 en attente mais `apt list` rapporte N > 0, le snapshot est incohérent — probablement un état transitoire (paquets bloqués, dépendances cassées) — et un nouveau WARN `updates.dist_upgrade_inconsistent` se déclenche avec `sudo apt update && sudo apt list --upgradable` pour investigation.

La cascade compte autant que le fix racine. La synthèse "Surface d'attaque" en fin de chaque audit avait une ligne `Mises à jour sécurité` qui lisait directement depuis les findings du moteur — si aucune clé `updates.security_pending` n'était émise, elle affichait `✔ à jour`. Évidemment "aucune clé émise" était exactement le bug. `bob/exposure.py` vérifie maintenant les deux nouvelles clés WARN et affiche `⚠ état inconnu — cache APT obsolète ou incohérent` au lieu du faux `✔`. Refuser de revendiquer "OK" quand la source de données n'est pas fiable est le bon contrat pour un outil de sécurité.

### Trois régressions cosmétiques depuis les VMs cross-distro

Elles ne changent pas le scoring mais elles changent la confiance. Un outil de hardening avec une sortie confuse ou contradictoire entraîne les utilisateurs à l'ignorer.

**Cas AppArmor "0 profil chargé"** (attrapé sur Kali, où l'install par défaut a le module noyau activé mais livre zéro paquet de profils). v0.4.3 émettait `AppArmor actif mais aucun profil en mode enforce (0 en plainte)`. La parenthèse se contredisait — impliquant que des profils en mode plainte existent alors qu'il n'y en a littéralement aucun. Le fix dans `bob/checks/mac_policy.py` distingue trois états explicitement :
- `enforce > 0` : chemin OK, langage actuel préservé.
- `enforce == 0 ET complain > 0` : chemin existant `apparmor_no_enforce` avec le conseil "passez en enforce" (ce cas s'applique à une vraie mauvaise config).
- `enforce == 0 ET complain == 0` (nouveau) : clé dédiée `apparmor_no_profiles` avec le message "AppArmor actif mais aucun profil chargé — le framework tourne sans rien à appliquer" et une recommandation d'installer `apparmor-profiles` / `apparmor-profiles-extra`. Le profil server applique une déduction de −1 ; le profil desktop garde ça en INFO.

**SMART "tous passés" sur systèmes uniquement virtuels** (attrapé sur Kali, /dev/vda). La sortie était :
```
ℹ /dev/vda — SMART non applicable (équipement virtualisé ou non supporté)
✔ Tous les disques ont passé le contrôle SMART — aucun attribut critique détecté
```
Logiquement incohérent — si aucune lecture SMART n'a tourné, rien n'a passé. `bob/checks/disk.py` n'émet maintenant le succès `disk.ok` "tous passés" que si au moins un check SMART **réel** (non-virtuel) a effectivement retourné un résultat. Sur les VMs et conteneurs où tous les disques sont virtuels, la ligne est simplement absente.

**Liste des ports ouverts DDNS rendue comme sous-items orphelins** (attrapé sur Mint test VM avec ddclient + masbateno.duckdns.org). Précédemment :
```
⚠ DDNS actif avec port(s) ouverts sans restriction — vérifiez que l'exposition est intentionnelle
ℹ Si cette exposition est intentionnelle : maintenez les services à jour...
    → 22/tcp
    → 80/tcp
```
Les lignes `→ 22/tcp` attachaient visuellement au conseil INFO mais appartenaient logiquement au WARN — un lecteur ne peut pas savoir quoi faire avec "22/tcp". Le fix dans `bob/checks/ddns.py` interpole la liste dans le message WARN lui-même : `DDNS actif avec port(s) ouverts sans restriction (22/tcp, 80/tcp) — vérifiez que l'exposition est intentionnelle`. La boucle de print orpheline dans `bob/runner.py` est retirée. Le champ `result.open_ports` est préservé pour les consommateurs programmatiques (diff baseline compare.py, sortie JSON, tests).

### Items reportés de l'audit v0.4.3, tous appliqués

**S4 redesign — lectures ssh symlink-safe.** v0.4.3 avait explicitement reporté ceci parce que le fix le plus simple (`_is_safe_config_path()` rejette tous les symlinks) aurait cassé les setups dotfiles légitimes où les utilisateurs symlinkent `~/.ssh/config` depuis un repo git-managé. Le bon design accepte les symlinks qui résolvent dans le home de l'owner mais rejette ceux pointant ailleurs (un attaquant avec write access sur le home d'un utilisateur plaçant un symlink vers `/etc/shadow` ferait fuiter le contenu de fichiers système dans le rapport d'audit). Nouveau helper `_is_safe_user_path(path, owner_home)` dans `bob/checks/_run.py` :

```python
def _is_safe_user_path(path, owner_home) -> bool:
    p = Path(path)
    if not p.is_absolute(): return False
    if p.is_symlink():
        try: target = p.resolve(strict=True)
        except OSError: return False
        home = Path(owner_home).resolve()
        try:
            target.relative_to(home)
            return True
        except ValueError:
            return False
    return True
```

Appliqué dans `bob/checks/ssh.py` sur `authorized_keys`, `~/.ssh/config`, et `known_hosts`. L'existant `_is_safe_config_path` (rejette tout symlink, pas d'exemption home-bounded) est conservé pour les chemins système comme `/etc/cron.d/`, `/etc/sudoers.d/`, et `/var/spool/cron/crontabs/` où tout symlink est suspect.

**M4 refactor — `_parse_ufw_covered_ports`.** Le fix v0.4.3 pour le faux positif `_is_covered_by_ufw` (où un numéro de port trouvé dans une IP source comme `192.168.1.22` "couvrait" faussement le port 22) était correct mais architecturalement fragile — il compilait un nouveau regex pour chaque port vérifié contre le même texte de règles UFW, et tout tweak futur risque de réintroduire le faux positif. Le refactor dans `bob/checks/ports.py` parse la chaîne de règles **une seule fois** au début de `check_ports()` dans un `set[tuple[int, str | None]]` de tuples (port, proto) couverts, puis les lookups deviennent des appartenance O(1). Le `_UFW_RULE_RE` au niveau module est ancré sur le début de la colonne "To" — la classe de faux positif est maintenant impossible par construction. Les deux formes (snapshot et string) d'`_is_covered_by_ufw` sont acceptées pour rétrocompatibilité avec tout caller externe.

**I2 vague 2 — `key=` sur les findings restants.** v0.4.3 couvrait les 4 fichiers les plus touchés (`docker.py`, `firewall_stack.py`, `network_context.py`, `ports.py`). Relancer l'audit sur les checks restants a révélé que `disk.py`, `docker_audit.py`, `desktop_apps.py`, `memory.py`, `suid_audit.py` étaient déjà à 100% de couverture key. Seuls `services.py` (10 sites) et `virtualization.py` (2 sites) avaient besoin de travail — les deux complétés ici. Le codebase a maintenant chaque appel `result.alert/warn/info/ok/add_deduction` câblé avec un `key=` stable pour `--ignore`, les profils d'audit, les consommateurs JSON, et les lookups `--explain`.

**Test de couverture i18n.** v0.4.3 avait eu une quasi-régression — quand le refactor M6 a retiré `logs.attempts` des deux fichiers de locale, 7 sites d'appel dans `bob/display.py` la référençaient encore. Les appels `_t("logs.attempts")` retournaient la clé brute en fallback, produisant la sentinelle `[logs.attempts]` que seul le test terrain a attrapée (post-push v0.4.3). Nouveau `tests/test_locale_coverage.py` tourne à chaque commit :

- Scanne tout `bob/**/*.py` pour les appels `t("KEY")` et `_t("KEY")` via regex, collecte les clés littérales.
- Asserte que chaque clé résout dans **les deux** `en.json` et `fr.json`.
- Asserte la parité structurelle EN/FR (même ensemble de clés feuilles).
- Asserte que les sections à prefixes dynamiques connues (`explain.*`, `services.exposure.*`, `services.state.*`) ont leurs dicts parents dans les deux locales.
- Inclut une baseline sanity (taille corpus de clés ≥ 200) pour qu'un regex cassé ne fasse pas silencieusement passer tous les autres tests trivialement.

Deux faux positifs dans des exemples de docstring (`bob/i18n.py` documente `t("samba.open_world")` et `t("log.blocked_attempts", count=42)` comme exemples illustratifs) sont listés dans `_KEY_EXCLUSIONS`. Tout futur faux positif peut être ajouté de la même façon.

### Écarté du rapport d'audit v0.4.3

- **M3** — `os.path` → `pathlib` dans 4 fichiers (`manage_logs.py`, `suid_audit.py:142,176,180,188`, `secure_boot.py:92`, `ssh.py:1000`). Cosmétique pur. Sera intégré dans une éventuelle release "consistency pass" (imports, type hints, etc.).
- **M7** — Résolution lazy de `_PLUGIN_DIR`. Re-confirmé rejeté de manière permanente. Le "gotcha" (SUDO_USER change mid-process) ne se produit pas dans le modèle d'exécution one-shot de BOB, et la tentative de fix en v0.4.3 cassait 20 tests qui font `patch("bob.registry._PLUGIN_DIR", ...)`.

### Tests

4489/4489 — +21 vs v0.4.3 :
- `tests/test_updates.py` (+10) : deux nouvelles classes de tests couvrant les nouveaux champs `UpdatesSnapshot`. `TestAptCacheStale` (5 tests) exerce le WARN cache-stale sous conditions fresh/stale/missing/boundary. `TestDistUpgradeInconsistency` (5 tests) exerce le WARN cross-check — le scénario précis du bug v0.4.3 est maintenant un test de régression (dist-upgrade retourne 0, apt list rapporte N → WARN).
- `tests/test_mac_policy.py` (+2) : `TestAppArmorNoEnforce::test_no_profiles_desktop_is_info` et `::test_no_profiles_server_deducts_one`, exerçant la nouvelle clé `apparmor_no_profiles` sur les deux chemins profile. L'existant `test_active_with_zero_profiles_at_all` a été réécrit pour asserter la nouvelle clé (il attendait précédemment l'ancienne sortie confuse `apparmor_no_enforce`).
- `tests/test_locale_coverage.py` (+9) : scan corpus complet, résolution locale EN, résolution locale FR, parité EN/FR, couverture des prefixes dynamiques. Le corpus contient 200+ clés statiques (la baseline sanity confirme que notre regex trouve assez de sites d'appel pour être significatif). Plus, en réponse à une review ChatGPT du fichier : negative lookbehind du regex resserré pour aussi rejeter `obj._t(...)` (qui précédemment matchait comme faux positif) ; ajout de `TestExplainNamespaceCoverage` (3 tests) qui génère les chemins attendus depuis la liste figée `EXPLAIN_KEYS` et asserte que chaque `explain.<clé>.{title,why,how}` existe dans les deux locales **en tant que string non-vide** (ceci ferme une zone aveugle — le prefix dynamique `("explain.", "explain")` précédent était un bypass qui masquait silencieusement toute feuille manquante) ; ajout de `TestPlaceholderParity` (1 test) qui asserte que l'ensemble des placeholders `{nom}` est identique entre en.json et fr.json pour chaque clé string commune (protège contre la classe de KeyError runtime `{count}` vs `{cnt}`).

### Validation production

Les fixes v0.4.3 confirmés fonctionnels sur **5 systèmes live différents** :
- **Linux Mint 22.3 dev box** : audit feature complet avec UFW actif, scénario DDNS, Docker installé, Samba, tous les checks rendus proprement sans sentinelles.
- **Linux Mint 22.3 test VM** : même moteur, état hôte différent — confirmé que la régression sentinelle `logs.attempts` avait été corrigée par le patch final v0.4.3.
- **Debian 13** : install minimal, smoke test du chemin cross-distro à travers `mac_policy`, chemin de logs UFW journald-only.
- **Kali Rolling** : 15 binaires SUID inattendus (kismet_cap_*) correctement flaggés comme outillage Kali-spécifique qui nécessite légitimement SUID ; NOPASSWD:ALL dans sudoers détecté avec la bonne sévérité ; AppArmor "0 profils chargés" a fait surface le bug de message confus corrigé ici ; corrélation COMPOUND risk (sudo NOPASSWD + SUID inattendus) a déclenché.
- **Ubuntu 26.04 LTS** : UFW inactif → ALERTE `firewall.inactive` déclenchée avec le `key=` ajouté en v0.4.2, l'entrée EXPLAIN_KEYS ajoutée en v0.4.3, la référence CIS, et le lien `bob --explain firewall.inactive`. La chaîne complète (key → ignore-able + profile-overridable + JSON-matchable + explain-resolvable) est maintenant validée en production sur une famille de distro toute neuve.

### Reporté à une release ultérieure

- Phase 2 Option A — migration systématique `Finding.template_vars` sur les ~37 checks non-pilotes. Toujours en piste pour v0.5.0+. `tests/test_template_vars_migration.py` continue à rendre la dette visible.
- Matrice CI multi-distros (Debian/Ubuntu/Mint/Kali en conteneurs) et PKGBUILD AUR — contribution communautaire bienvenue, non bloquant.
- Cleanup cosmétique M3 (os.path → pathlib).

---

## [v0.4.3] — 15-05-2026

**Release de rattrapage doc qui s'est étendue en passe de hardening.** Cette release a commencé comme la clôture de deux dettes explicitement reportées par v0.4.2 (4 entrées `EXPLAIN_KEYS`, synchro CHANGELOG court). Chemin faisant, un nouvel audit agent sur la totalité du codebase v0.4.2 a fait remonter **1 critique + 5 importants + 8 mineurs + 6 suggestions**. Tous corrigés dans la même release.

Le rapport d'audit complet est documenté inline ci-dessous, organisé par criticité. Faits marquants :

- **C1 (critique)** — `bob --json --json-full` crashait sur chaque système avec `AttributeError`. `bob/json_output.py` lisait 5 attributs (`fail2ban_active`, `auto_updates_enabled`, `apparmor_mode`, `apparmor_enforced`, `apparmor_complain`) depuis `HardeningSnapshot` après leur migration vers `mac_policy.py`. Les lectures mortes ont été supprimées ; la sortie JSON expose désormais uniquement les vrais champs. Un test de régression a été ajouté à `tests/test_json_schema.py::TestFullModeWithOptionalSnapshots` couvrant le chemin `full=True` + `hardening_snapshot` — exactement la lacune qui avait laissé le bug passer en v0.4.2.

- **I1 (important — échec silencieux)** — `datetime.strptime("%b ...")` parse les abréviations de mois anglais en utilisant le `LC_TIME` du **process Python**. Le `LC_ALL=C` des subprocess n'affecte que la sortie de la *commande*, pas Python. Sous `LC_TIME=fr_FR.UTF-8` (courant sur les installations françaises), `strptime("May 14 ...")` levait `ValueError` silencieusement, causant `_read_cert_expiry` à retourner "could not parse notAfter" pour chaque certificat TLS et `_parse_timestamp` à ignorer silencieusement chaque ligne UFW au format syslog. Le score d'audit était systématiquement gonflé sur les systèmes français parce que les certificats expirants et les tentatives de bruteforce étaient invisibles. Nouveau helper `_parse_english_month_day()` dans `bob/checks/_run.py` parse par lookup dict, totalement indépendant de la locale.

- **I2 (important — contrat incomplet)** — Environ 30 appels `result.alert()/.warn()/.info()/.ok()/.add_deduction()` dans `docker.py`, `firewall_stack.py`, `network_context.py` et `ports.py` n'avaient pas l'argument `key=`. Même classe de bug que le C1 v0.4.2, généralisée aux 4 fichiers les plus touchés. Sans `key=`, les findings ne peuvent être matchés ni par `--ignore`, ni par les profils d'audit, ni par les consommateurs JSON externes. Les ~6 fichiers restants ont une densité plus faible de keys manquants et sont tracés pour une passe future.

- **I3 (important — rendu email cassé)** — `bob/report_markdown.py::_inline_format` construisait d'abord le HTML `<a href="...">label</a>` puis appelait `html.escape()` sur le résultat. Tous les liens dans les rapports email rendaient `&lt;a href=&quot;...&quot;&gt;label&lt;/a&gt;` en texte littéral. Ordre d'opérations inversé : escape du texte brut d'abord, puis traduction markdown vers HTML.

- **I4 (important — sous-comptage du score)** — Le regex `_is_covered_by_ufw` n'était pas ancré : il matchait le numéro de port n'importe où sur une ligne de règle UFW, y compris dans les champs IP source. Une IP source comme `192.168.1.22` "couvrait" faussement le port 22. Conséquence : les ports publics réellement non couverts étaient silencieusement classés comme couverts, donc l'audit rapportait un score plus haut que ce que le système méritait. Regex maintenant ancré sur la colonne "To" (juste après `[ N]`).

- **I5 (important — perte silencieuse de données cron)** — `_validate_custom_cron` ne contrôlait que les champs entiers pleins. Des valeurs comme `0-1000 0 * * *` ou `*/200 * * * *` passaient le validateur BOB et étaient ensuite rejetées par cron au parse time, perdant silencieusement la planification. Validateur complet ajouté : ranges, listes, valeurs de step, les 5 champs, avec les bornes correctes (minute 0-59, heure 0-23, jour-du-mois 1-31, mois 1-12, jour-de-la-semaine 0-7).

En plus, les **8 mineurs** (clés locale mortes, cohérence `_C_LOCALE_ENV`, anti-pattern concat i18n, regex redondant, support unités template systemd) et **5 sur 6 suggestions** (env sysinfo, protection symlink sur fichiers cron, logging fallback domain_scores, `__all__`) ont été appliqués. Les 4 points écartés (M3 cosmétique, M4 négligeable, M7 cassait 20 tests au revert, S4 discussion design nécessaire) sont documentés ci-dessous pour traçabilité.

Puis le rattrapage doc initialement prévu :

1. **Les 4 clés firewall promues dans `EXPLAIN_KEYS`.** En v0.4.2 le fix C1 de l'audit agent avait câblé quatre clés (`prerequisites.ufw_missing`, `firewall.inactive`, `firewall.policy_open`, `firewall.policy_unknown`) comme `Finding.key` pour que `--ignore`, les profils d'audit et les consommateurs JSON puissent les matcher. Mais `bob --explain firewall.policy_open` répondait encore "not found" parce que les clés n'étaient pas dans `EXPLAIN_KEYS` et n'avaient pas de contenu title / why / how / CIS associé. Ce contenu avait été reporté parce que rédiger quatre explications complètes en anglais et français est un vrai travail documentaire, pas un fix rapide. Cette release fait ce travail.

2. **CHANGELOG.md (court) corrigé pour v0.4.2.** La section détaillée v0.4.2 ouvrait par "**Aucun changement de code** · 4449/4449 tests (inchangé)" ce qui était factuellement faux : la passe de hardening livrée avec v0.4.2 a modifié 11 fichiers Python et ajouté 3 tests. `CHANGELOG_FULL.md` était déjà correct ; la version courte ne l'était pas. La section a été réécrite avec le détail complet de la passe de hardening (C1, C2, I1-I5, M1-M5, S1-S3). La release v0.4.2 sur PyPI et GitHub est inchangée — c'est un correctif documentaire rétroactif dans `main`.

### Pourquoi une release séparée

La tentation était d'amender v0.4.2 et de force-pusher. Deux raisons de ne pas le faire :

- Le tag v0.4.2 et l'artefact PyPI sont immuables. Une "v0.4.2 avec docs corrigées" sur PyPI est impossible. Une release séparée trace la correction documentaire visiblement.
- Un utilisateur qui lance `bob --version` sur v0.4.2 puis `bob --explain firewall.policy_open` verrait toujours "not found". Avec v0.4.3 il voit du vrai contenu. Le bump de version est la vérité.

### Changements

- **`bob/explain.py`** — le libellé du groupe change de "Firewall Logging" (qui ne contenait que `firewall.logging_off`) à "Firewall", et les quatre nouvelles clés le rejoignent. Le commentaire TODO qui marquait le report en v0.4.2 a disparu. La longueur de `EXPLAIN_KEYS` passe de 112 à 116.
- **`bob/locales/en.json`** — nouvelle entrée `explain.prerequisites.ufw_missing.{title,why,how}`, et trois nouvelles entrées sous `explain.firewall.{inactive,policy_open,policy_unknown}.{title,why,how}`. Chaque entrée suit la même forme que l'`explain.firewall.logging_off` pré-existante : un titre court, un paragraphe expliquant pourquoi c'est un risque de sécurité (pas seulement "ce que" le finding signifie), et une procédure de remédiation numérotée.
- **`bob/locales/fr.json`** — les quatre mêmes entrées en français, traduction idiomatique (pas littérale).
- **`bob/data/cis_refs.json`** — 4 nouvelles entrées. `prerequisites.ufw_missing` → CIS Ubuntu 22.04 L1 3.5.1.1 "Ensure ufw is installed". `firewall.inactive` → CIS 3.5.1.3 "Ensure ufw service is enabled". `firewall.policy_open` et `firewall.policy_unknown` → CIS 3.5.1.7 "Ensure ufw default deny firewall policy" (les deux clés mappent au même contrôle parce que le cas "unknown" est un échec de parsing de la même sortie de statut que `policy_open` détecte positivement).
- **`tests/test_explain.py`** — l'assertion en dur `assert len(EXPLAIN_KEYS) == 112` passe à `116`. Cette assertion est le freeze explicite : quand EXPLAIN_KEYS change, le test force la mise à jour dans le même commit. C'est le workflow voulu.
- **`tests/test_display_explain_hint.py`** — deux tests utilisaient `firewall.inactive` comme exemple de clé de finding qui ne *devait pas* déclencher de hint `--explain` (parce qu'elle n'était pas dans EXPLAIN_KEYS). Maintenant qu'elle y est, ces tests auraient correctement échoué. Le fix remplace l'exemple par une clé fictive `test.nonexistent_key` pour que les tests restent résilients face aux futures additions de EXPLAIN_KEYS.
- **`CHANGELOG.md`** + **`CHANGELOG_FR.md`** — section détaillée v0.4.2 réécrite avec le contenu de la passe de hardening. v0.4.2 avait déjà ce contenu dans `CHANGELOG_FULL.md` ; ceci met la version courte en cohérence.
- **Bump de version** — `pyproject.toml`, `bob/__init__.py`, trois URLs `$id` de schémas, deux badges README, tous de `0.4.2` → `0.4.3`.

### Tests

4464/4464 — +12 vs v0.4.2. Aucune nouvelle fonction de test ; la croissance du compteur est mécanique parce que `tests/test_explain.py` a trois blocs `@pytest.mark.parametrize("key", EXPLAIN_KEYS)` (vérification title, vérification headers WHY/HOW, vérification ref CIS), et l'ajout de 4 clés à `EXPLAIN_KEYS` produit 12 nouvelles invocations paramétrées.

Validé bout-en-bout manuellement :
- `python3 -m bob --explain firewall.inactive` en anglais et en français affiche le titre, le paragraphe WHY IT IS A RISK, la procédure HOW TO FIX numérotée, et la ref CIS.
- Idem pour `firewall.policy_open`, `firewall.policy_unknown`, `prerequisites.ufw_missing`.
- `bob --explain firewall.logging_off` fonctionne toujours (vérification de régression sur la clé pré-existante).
- `bob --explain list` affiche le groupe renommé "Firewall" avec les 5 clés.

### Reporté à une release ultérieure

Cette release ne change pas le travail Phase 2 reporté. La migration systématique des ~37 checks non-pilotes restants vers `Finding.template_vars` (Phase 2 Option A) reste tracée pour **v0.5.0+**. Le test de progrès de migration Phase 2 (`tests/test_template_vars_migration.py`) continue à rendre cette dette visible.

La matrice CI multi-distros et le PKGBUILD AUR sont aussi toujours reportés — contributions communautaires bienvenues, non bloquants.

---

## [v0.4.2] — 14-05-2026

**Phase 3 de la roadmap distro-ready — discipline packaging.** Cette release ajoute les artefacts dont les mainteneurs distros ont besoin pour packager BOB sans patcher le source. Trois man pages, un paquet source Debian ciblant 3 paquets binaires (`bob-core` / `bob-tui` / `bob` meta), une spec RPM Fedora, un profil AppArmor, un threat model `SECURITY.md`, et une politique formelle de support Python. Un audit agent pré-release a aussi fait remonter 2 critiques + 5 importants + 4 mineurs + 1 suggestion — tous corrigés dans la même release (section "Passe de hardening" ci-dessous). 4452/4452 tests (+3 depuis `tests/test_template_vars_migration.py`).

L'intention stratégique : BOB a franchi le cap "est-ce assez stable ?" en Phases 1 & 2. Le dernier obstacle à l'adoption distro est l'absence des artefacts standards que chaque mainteneur distro s'attend à trouver upstream. Cette release ferme ce trou.

---

### `SECURITY.md` — threat model et politique de disclosure

**Fichiers :** `SECURITY.md` (nouveau)

#### Problème

Jusqu'à v0.4.2, la posture sécurité de BOB était implicite. Un packager distro lisant le repo n'avait aucune réponse formelle à : qui est l'adversaire ? Contre quelles menaces BOB défend ? Qu'est-ce qui est hors scope ? Où signaler une vulnérabilité ? Sans ces réponses, les packagers soit devinent (dangereux), soit passent leur chemin (pire).

#### Implémentation

`SECURITY.md` (~150 lignes) couvre :

- **Tableau des versions supportées** avec politique EOL : seul le minor courant reçoit des patches sécurité.
- **Canal de signalement** : `cedricclauzel@mailo.com` avec préfixe `[BOB security]`. Acquittement 7 jours, fenêtre fix 30 jours pour les issues haute-sévérité.
- **Threat model** : ce qu'est BOB (outil audit-only invoqué par utilisateur privilégié) vs ce qu'il n'est PAS (pas de daemon, pas d'agent remote, pas de défense active).
- **Modèle d'adversaire** : trois hypothèses (utilisateur invoquant trusted, layout filesystem sain, package manager intact). BOB est post-compromission, pas pré-.
- **Tableau frontières de confiance** : config user-contrôlée (JSON Schema + ANSI sanitization + size limits), contenu fichiers système (bounded reads, `_C_LOCALE_ENV`), sortie subprocess (timeouts partout, pas de `shell=True` hors `--fix`).
- **Hors scope** : compromission root préalable, attaques niveau noyau, vulnérabilités applicatives.
- **Contrat mode `--fix`** : jamais d'exécution sans confirmation `y`.
- **Avertissement plugins** : `~/.config/bob/checks.d/*.py` ne sont PAS sandboxés.
- **Surface réseau** : 2 appels HTTPS sortants, tous deux gatés par `--offline`. Pas de télémétrie.
- **Manipulation de données** : permissions fichiers, comportement `chown_to_sudo_user` depuis v0.3.6.
- **Recommandations defense-in-depth pour packagers** : profil AppArmor en mode complain par défaut ; `pipx` comme chemin d'install recommandé.
- **Politique de disclosure** : embargo 30 jours extensible, contributeurs crédités sauf demande d'anonymat.

#### Notes de design

- La liste "ce que BOB n'EST PAS" est intentionnellement explicite. Les outils d'audit sont parfois mal classés comme défenses ; clarifier la frontière d'emblée évite les malentendus.
- Le tableau frontières de confiance map chaque traversée à la mitigation côté code déjà en place — ce ne sont pas des promesses aspirationnelles mais des checks que la suite de tests valide déjà.

---

### Man pages

**Fichiers :** `man/bob.1` (nouveau, ~280 lignes), `man/bob.conf.5` (nouveau, ~80 lignes), `man/bob-profile.5` (nouveau, ~100 lignes)

#### Problème

Un paquet Debian / Fedora sans man pages échoue les checks `binary-without-manpage` lintian/rpmlint et est plus dur à découvrir avec `man -k`. Jusqu'à v0.4.2 BOB livrait un `--help` mais pas de `man bob`.

#### Implémentation

Trois man pages groff écrites à la main (validées avec `man -l` et `groff -man -Tutf8`) :

- **`bob(1)`** — page user-facing principale. Sections : `NAME`, `SYNOPSIS`, `DESCRIPTION`, `OPTIONS` (sous-groupées par finalité), `EXIT CODES` (contrat API publique stable rappelé ici), `JSON OUTPUT`, `FILES`, `ENVIRONMENT`, `SECURITY`, `SEE ALSO`, `AUTHOR`, `COPYRIGHT`.
- **`bob.conf(5)`** — format fichier config.
- **`bob-profile(5)`** — format fichier profil d'audit.

Écrites à la main plutôt que générées via `argparse-manpage` pour éviter d'ajouter une dépendance de build. Le coût : updates manuels quand la CLI change — mais la CLI fait partie de l'API publique stable depuis Phase 1, peu de changements attendus.

---

### Paquet source Debian

**Fichiers :** `debian/control`, `debian/copyright`, `debian/changelog`, `debian/rules`, `debian/source/format`, `debian/bob-core.install`, `debian/bob-tui.install`, `debian/bob-core.docs`, `debian/bob-core.manpages`, `debian/apparmor.d/bob` (tous nouveaux)

#### Problème

La convention de packaging Debian est un dossier `debian/` à la racine du projet contenant un set strict de fichiers. Sans lui, le downstream Debian est impossible.

#### Implémentation

**Trois paquets binaires déclarés dans `debian/control` :**

| Paquet binaire | Contient | Pourquoi split |
|---|---|---|
| `bob-core` | Pipeline audit, CLI, checks, scoring, JSON, locales, schemas, man pages, SECURITY.md | Tourne headless. Pas de dep curses. Adapté conteneurs, CI, serveurs minimaux. |
| `bob-tui` | Sous-package `bob/tui/` (TUI curses) | Optionnel. Recommandé sur stations de travail, skip sur serveurs headless. |
| `bob` | Meta-package dépendant des deux | `apt install bob` installe tout. |

`Build-Depends` standard `debhelper-compat (= 13)` + `pybuild-plugin-pyproject`. `Rules-Requires-Root: no`.

`Recommends` / `Suggests` sur `bob-core` listent les soft dependencies avec lesquelles BOB intègre au moment de l'audit (`ufw`, `fail2ban`, `rkhunter`, `clamav`, `auditd`, `aide`, `unattended-upgrades`, `smartmontools`, `apparmor`, `fwupd`).

**`debian/copyright`** au format DEP-5 avec stanzas distinctes pour le source, les données curées, les locales, les schemas. Tout MIT ; les références CIS sont notées explicitement comme mappings (pas redistribution du texte standard CIS).

**`debian/rules`** utilise pybuild. Un `override_dh_install` installe les man pages et `SECURITY.md` dans `bob-core`.

**`debian/source/format`** : `3.0 (quilt)`.

**Fichiers split (`bob-core.install`, `bob-tui.install`)** listent les chemins explicites pour que dh_install sache quel module va où.

#### Profil AppArmor

`debian/apparmor.d/bob` (~140 lignes). Livré en mode `complain` par défaut — l'utilisateur opte pour `enforce` après validation sur sa distro/version. Permet :

- read sur `/etc/`, `/proc/`, `/sys/`, `/var/log/`, dirs état package manager
- read+write sur `~/.config/bob/` et `~/.local/share/bob/`
- exec (via `Pix`) d'une whitelist fermée de ~30 outils système
- TCP sortant — le flag `--offline` au niveau application est la gate, pas le profil

#### Notes de design

- **Trois binaires plutôt qu'un.** Un paquet `bob` unique forcerait chaque image serveur / CI à tirer curses pour une TUI jamais utilisée. Split `bob-core` permet aux déploiements headless de rester légers sans désactiver de fonctionnalités.
- **Pourquoi mode complain par défaut pour AppArmor.** BOB exec beaucoup de binaires dont les chemins varient entre distros. Enforce génèrerait de faux denials. Complain laisse l'utilisateur observer puis graduer.

---

### Spec RPM pour Fedora COPR

**Fichiers :** `packaging/rpm/bob.spec` (nouveau)

#### Problème

Les conventions de packaging Fedora divergent de celles Debian : un seul `.spec`, `pyproject-rpm-macros`, pas de dossier `debian/`, pas de split Python core/extras typique. Sans spec, l'adoption Fedora COPR / RHEL EPEL est impossible.

#### Implémentation

Un paquet binaire `bob` unique sur Fedora (pas de split). La spec utilise `pyproject_wheel` / `pyproject_install` / `pyproject_save_files bob` pour déléguer au pipeline `pyproject.toml`.

`%check` exécute le smoke test plus la suite pytest complète. Sur Fedora COPR, ça attrape toute régression induite par le packaging.

Man pages et `SECURITY.md` installés via `install -D` explicites pendant `%install`.

`Recommends` et `Suggests` miroirent le control Debian avec les noms de paquets Fedora (`firewalld` vs `ufw`, `audit` vs `auditd`).

#### Notes de design

- **Pourquoi un répertoire `packaging/rpm/` séparé.** La convention Debian met tout sous `debian/`. RPM n'a pas d'équivalent racine — `packaging/` garde les deux systèmes visiblement séparés tout en restant upstream.
- **Pas de lignes `Patch:`.** La spec build upstream tel quel.

---

### Politique de support Python

**Fichiers :** `DOCUMENTS/README_TECH.md` + FR — nouvelle section

#### Problème

Les mainteneurs distros planifiant leurs fenêtres de compatibilité Python ont besoin de savoir si BOB supportera Python 3.10 dans 2 ans. Sans politique formelle, chaque EOL Python devient une renégociation.

#### Implémentation

Nouvelle section "Politique de support Python" dans `README_TECH.md` (et FR) s'engage sur **N et N-2** où N est la stable upstream actuelle. À partir de v0.4.2 :

| Python | Statut |
|---|---|
| 3.13 | ✅ supporté (à sortie) |
| 3.12 | ✅ CI par défaut |
| 3.11 | ✅ supporté |
| 3.10 | ✅ le plus ancien |
| 3.9 | ❌ EOL depuis v0.2.3 |

Procédure d'abandon s'étale sur au moins 3 minor BOB releases (valider / annoncer / retirer) pour préavis minimum 6 mois. Miroir des cycles freeze Debian / Fedora.

---

### Tests

4452/4452 — +3 vs v0.4.1, tous issus de `tests/test_template_vars_migration.py` (S1) qui rend visible la dette de migration Phase 2. La passe de hardening (C1, C2, I1-I5, M1-M5, S2, S3) a modifié 11 fichiers Python ; la suite existante couvrait tous ces fichiers et est restée verte tout du long.

Validation séparée :
- `groff -man -Tutf8` et `man -l` parsent les 3 man pages sans erreur.
- Les 3 fichiers schema JSON chargent et valident via `jsonschema`.

---

### Contexte roadmap

| Phase | Statut |
|---|---|
| Phase 1 (contrats) | ✅ v0.4.0 |
| Phase 2 (découplage archi) — Option B additive | ✅ v0.4.1 |
| Phase 2 — Option A breaking | ⏳ v0.5.0+ |
| **Phase 3 (discipline packaging)** | **✅ v0.4.2** |
| Phase 3 finitions (CI multi-distro, PKGBUILD AUR) | ⏳ contributions communautaires v0.4.x |

Après v0.4.2, BOB est **packaging-complet** pour le chemin AUR/COPR et **prêt pour Debian unstable** sous réserve de validation lintian-clean + parrainage upstream.

---

### Hardening pass — audit pré-release

**Fichiers :** `bob/checks/firewall.py`, `bob/checks/ssl_certs.py`, `bob/checks/virtualization.py`, `bob/_paths.py`, `bob/i18n.py`, `bob/registry.py`, `bob/watch.py`, `bob/__main__.py`, `bob/compare.py`, `bob/formatter.py`, `man/bob.1`, `debian/apparmor.d/bob`, `packaging/rpm/bob.spec`, `tests/test_template_vars_migration.py` (nouveau), `microsoft.gpg` (supprimé)

#### Problème

Un audit complet pré-release (agent general-purpose, ~3500 lignes source consultées) a fait remonter **2 critiques + 5 importants + 4 mineurs + 1 suggestion**. Les deux findings critiques se concentraient sur les artefacts de packaging (écrits sans cross-check mécanique vs le code), confirmant que cette catégorie d'artefact mérite la même rigueur que le source.

#### Corrections critiques

**C1 — Findings `firewall.py` sans `key=`** (`bob/checks/firewall.py:154,165,178,183`). Trois appels `result.alert()` (`prerequisites.ufw_missing`, `firewall.inactive`, `firewall.policy_open`) et un `result.add_deduction()` n'avaient pas de `key=`. Conséquence : les alertes max-criticité ne pouvaient être ni `--ignore`ées, ni profilées, ni matchées par les consommateurs JSON (qui utilisent tous `Finding.key` / `Deduction.key`). Fix : ajout de `key=` aux 4 sites + 4 autres findings de la même fonction pour cohérence. (`bob/explain.py` non étendu — ajouter ces 4 clés à `EXPLAIN_KEYS` requiert d'écrire titre/why/how/CIS complets dans `en.json` et `fr.json` pour chacune, **reporté explicitement en v0.4.3** avec un TODO inline près du groupe "Firewall Logging" ; `bob --explain firewall.policy_open` dira "not found" en v0.4.2 mais `--ignore` / profils / matching JSON fonctionnent correctement.)

**C2 — Profil AppArmor incomplet + mauvais chemin** (`debian/apparmor.d/bob`). 10 binaires que BOB exec étaient absents du profil (`df`, `lsblk`, `dpkg-query`, `getenforce`, `apt-get`, `find`, `ps`, `netstat`, `ntpstat`, `docker`) — en mode `enforce`, les checks disk/SUID/MAC/updates/SMTP/NTP/docker/desktop-apps retournaient tous vide. De plus, la ligne 85 déclarait `/usr/local/sbin/bob-*` rw alors que `bob/cron.py:30` écrit dans `/usr/local/bin/bob-{slug}`. Donc `--install-cron` échouerait silencieusement sous enforce. Fix : ajout des 10 binaires manquants + correction du chemin.

#### Corrections importantes

**I1+I2 — `_C_LOCALE_ENV` manquant sur 3 sites subprocess** (`bob/checks/ssl_certs.py:283`, `bob/checks/virtualization.py:166,178`). Le threat model SECURITY.md promet que tous les appels subprocess utilisent `_C_LOCALE_ENV` pour éviter le parsing dépendant de la locale. `openssl x509 -enddate` émettrait "mai 14" sur locale FR qui ferait échouer `datetime.strptime(..., "%b ...")` ; `ip link show` et `snap connections --all` avaient le même risque. Fix : passage de `env=_C_LOCALE_ENV` aux 3 appels.

**I3 — Env var legacy `UFW_AUDIT_SHARE`** (`bob/_paths.py`). Le projet s'appelait "UFW Audit" avant v0.1.0 ; la variable env share-dir avait gardé l'ancien nom. Les packagers étaient confus. Renommée en `BOB_SHARE` (le contrat documenté depuis v0.4.2). `UFW_AUDIT_SHARE` reste accepté pour la rétrocompat — quand les deux sont définis, `BOB_SHARE` gagne. Logué en INFO quand seul le nom legacy est utilisé. Documenté dans `man/bob.1` section ENVIRONMENT.

**I4 — RPM `Recommends: firewalld`** (`packaging/rpm/bob.spec`). BOB lit `ufw status` exclusivement — recommander `firewalld` était un guess côté Fedora qui induirait en erreur les packagers. Corrigé en `Recommends: ufw` avec commentaire explicatif inline.

**I5 — `bob/watch.py` ne thread pas `user_config`** (ligne 80-83). Le mode `--watch` perdait silencieusement la whitelist SUID de l'utilisateur car `run_checks()` était appelé sans `user_config=`. Whitelist `[]` à chaque tick → faux positifs SUID répétés. Fix : thread `user_config` à travers `run_watch()` depuis `__main__.py`.

#### Corrections mineures

- **M1** — Suppression de `microsoft.gpg` untracked (résidu d'`apt-add-repository` à la racine du repo).
- **M2** — Clarification du docstring `bob/formatter.py` : "Status: this module is a public API for external integrators. No production code path in BOB itself calls format_finding / format_deduction in v0.4.x." Lève l'ambiguïté que le formatter serait le chemin de rendu interne.
- **M4** — Exposition de `bob.compare.BASELINE_PATH` (sans underscore) comme symbole public ; `_BASELINE_PATH` conservé comme alias transitionnel. `bob/__main__.py` mis à jour pour utiliser le nom public.
- **M5** — Ajout `Suggests: apparmor`, `Suggests: apparmor-utils` à la spec RPM pour symétrie avec le paquet Debian.

#### Suggestion implémentée

**S1 — `tests/test_template_vars_migration.py`** (nouveau, 3 tests) : track la dette de migration Phase 2 de manière visible. Le set actuel `_MIGRATED_CHECKS_V0_4_2` est `{ssh.py, hardening.py, firewall.py}` — quand de nouveaux checks gagnent des `template_vars=`, le set est mis à jour dans le même commit. Une régression qui retirerait accidentellement `template_vars` d'un check migré échoue le CI immédiatement.

#### Tests

4449 → **4452** (+3 du nouveau test de migration). Tous les tests existants restent verts.

#### Note qualité finale : 8.5/10 → 9/10

L'audit pré-release a fermé le gap entre les promesses SECURITY.md et la réalité du code, corrigé les 2 vrais bugs du chemin runtime (C1 et I5 — tous deux à conséquence utilisateur visible), et aligné les artefacts de packaging avec le source. Le travail restant vers 10/10 est la migration systématique des 37 checks non-pilotes vers `template_vars`, explicitement multi-release et tracée par le nouveau test.

---

## [v0.4.1] — 14-05-2026

**Phase 2 de la roadmap distro-ready — découplage architectural.** Trois zones traitées : finalisation `--offline`, isolation curses sous `bob/tui/`, et représentation findings/deductions indépendante de la locale via `template_vars` additif. Plus une passe de hardening post-revue sur `bob/formatter.py` (API resserrée, tests edge-case). Tous les changements sont non-breaking (additifs). 4449/4449 tests (+19).

La roadmap Phase 2 vise un paquet Debian `bob-core` installable sans curses et sans texte localisé enfoui dans la sortie JSON. Cette release pose les fondations sans casser l'API existante.

---

### Zone 2.1 — Mode `--offline` strict finalisé

**Fichiers :** `tests/test_webhook.py`

#### Problème

Le flag `-o` / `--offline` existe depuis v0.4.0 et gatait déjà les deux sites touchant le réseau (`bob.sysinfo.get_public_ip` HTTP, `bob.webhook.send_webhook` POST). Manquait pour un vrai audit distro-ready : un inventaire bout en bout de tous les appels qui pourraient toucher le réseau, et des tests d'intégration qui figent le contrat.

#### Implémentation

Audit réseau (survey only, pas de modif de code) :

| Site | Verdict |
|---|---|
| `bob/sysinfo.py:158` `urllib.request.urlopen` (`get_public_ip`) | ✅ gaté par `offline=True` |
| `bob/webhook.py:send_webhook` POST HTTP | ✅ gaté par `__main__.py:277` |
| `bob/checks/kernel_modules.py` `apt-cache policy` | ✅ lecture cache local |
| `bob/checks/firmware.py` `fwupdmgr get-updates` | ✅ lecture cache local |
| `bob/checks/auth_log.py` `journalctl` | ✅ local |
| `bob/checks/ssl_certs.py` `openssl x509 -in <file>` | ✅ fichier local |
| Autres (`ss`, `iptables`, `nft`, …) | ✅ tous locaux |

Conclusion : aucun site réseau oublié, le plumbing `--offline` est complet.

3 nouveaux tests dans `tests/test_webhook.py` qui figent le contrat (CLI parse OK, webhook skip, urllib short-circuit).

#### Notes de design

Pourquoi un test miroir de la branche de décision plutôt qu'un test d'intégration full `_run()` : l'orchestration pipeline tire des dizaines de dépendances (FS, subprocess, locale, ScoreEngine, …). Mirorer la condition à 2 lignes donne la même couverture pour une fraction du coût de maintenance.

---

### Zone 2.2 — Sous-package curses `bob/tui/`

**Fichiers :** nouveau `bob/tui/__init__.py`, `bob/cron_ui.py` → `bob/tui/cron.py` (git mv), `bob/cron.py` (sites d'import), `DOCUMENTS/README_DEV.md` (FR + EN)

#### Problème

Pour un paquet Debian `bob-core` qui tourne dans des conteneurs minimaux (sans curses), le reste de `bob.*` doit rester importable sans curses installé. Les `import curses` étaient déjà lazy (à l'intérieur des fonctions) mais `bob/cron_ui.py` vivait au top-level de `bob.*`, suggérant qu'il faisait partie du module core. Un packager lisant la structure du projet ne pouvait pas dire que `cron_ui` était optionnel.

#### Implémentation

- Nouveau `bob/tui/__init__.py` documente la politique du sous-package.
- `git mv bob/cron_ui.py bob/tui/cron.py` (historique préservé).
- `bob/cron.py` : 2 sites d'import lazy updates, docstring module ajusté.
- `setuptools.packages.find` config (`include = ["bob*"]`) couvre déjà `bob.tui` automatiquement — pas de changement `pyproject.toml`.
- `DOCUMENTS/README_DEV.md` + FR : arbre de structure mis à jour.

#### Notes de design

- **Pourquoi un sous-package plutôt qu'une distribution séparée.** Le split en `bob-core` + `bob-tui` sur PyPI est une préoccupation de packaging, pas de code. La distribution `bob` continue à tout livrer ; le layout sous-package est la fondation pour qu'un futur packager Debian puisse split sans toucher au code.
- **`explain.py`, `manage_logs.py`, `cron.py` non déplacés.** Mélangent logique métier et bits TUI. Out of scope.

---

### Zone 2.3 — Findings indépendants de la locale via `template_vars` additif

**Fichiers :** `bob/scoring.py`, `bob/json_output.py`, nouveau `bob/formatter.py`, `bob/checks/ssh.py`, `bob/checks/hardening.py`, `bob/checks/firewall.py`, nouveau `tests/test_formatter.py`, `tests/test_json_schema.py`

#### Problème

Jusqu'à v0.4.0, `Finding.message` et `Deduction.reason` étaient des strings déjà formatées dans la locale active. Les consommateurs externes du JSON n'avaient aucun moyen de :
- Rendre le même finding dans une autre locale.
- Matcher les findings par leur clé sémantique stable sans parser la chaîne localisée.

`Finding.key` (ajouté en Phase 1) donnait un nom stable, mais les variables interpolées dans le template étaient perdues. Un client voulant "la liste des ciphers signalés comme faibles" devait parser le `message` localisé.

L'objectif Phase 2 est `bob.core` *pur* — sans `print()`, sans `_t()`, sans curses. Cette release pose le premier pas additif : exposer `(key, template_vars)` partout en parallèle du legacy `message`/`reason`.

#### Implémentation

##### Deux nouveaux champs dataclass

```python
@dataclass
class Deduction:
    ...
    template_vars: dict = field(default_factory=dict)   # NOUVEAU

@dataclass
class Finding:
    ...
    template_vars: dict = field(default_factory=dict)   # NOUVEAU
```

Le nom `template_vars` est délibéré : il documente que le dict contient les variables passées à `.format(**kwargs)` du template i18n. Nous avons évité `context` (déjà pris par `Deduction.context: str` signifiant le scope réseau) et `vars`/`params` (trop générique).

##### Helpers de convenance acceptent `template_vars=`

`CheckResult.add_finding`, `.ok`, `.info`, `.warn`, `.alert`, `.add_deduction` gagnent tous un kwarg optionnel `template_vars=None`. Les sites d'appel legacy ne nécessitent ZÉRO changement.

##### Nouveau module `bob.formatter`

`format_finding(finding, lang=None) -> str` et `format_deduction(deduction, lang=None) -> str` implémentent le rendu indépendant de la locale. Ordre de résolution :

1. Si `key` est défini ET `template_vars` non-vide → render `_t(key, **template_vars)`.
2. Si `key` défini sans template_vars → render `_t(key)` si la résolution est clean.
3. Sinon fallback sur `finding.message` / `deduction.reason` (chemin legacy).

Le fallback à l'étape 3 rend le formatter 100% rétrocompatible.

Le paramètre `lang` est réservé pour une future API permettant de rendre le même finding dans plusieurs locales sans flipper la locale du processus.

##### Trois checks pilotes migrés

- **`bob/checks/ssh.py`** — `_check_host_keys` (4 sites) avec `template_vars={"name": ..., "bits": ..., "type": ...}` selon le cas.
- **`bob/checks/hardening.py`** — `tcp_syncookies_ok` avec `value=snapshot.tcp_syncookies`.
- **`bob/checks/firewall.py`** — `firewall.logging_ok` et `logging_verbose` avec `level=level`.

Dans chaque cas, le `message=_t("key", **vars)` existant est préservé (compat) et `template_vars={...vars...}` ajouté en parallèle.

##### `template_vars` exposé dans la sortie JSON

`bob/json_output.py` sérialise désormais `template_vars` sur chaque deduction et chaque finding (full mode) :

```json
{
  "deductions": [
    {
      "reason": "DSA host key: ssh_host_dsa_key",
      "points": 1,
      "key": "ssh.host_key_dsa",
      "template_vars": {"name": "ssh_host_dsa_key"}
    }
  ]
}
```

Le champ est toujours présent (dict vide pour les checks legacy). C'est additif.

#### Tests

`tests/test_formatter.py` (nouveau, 10 tests) : ordre de résolution, roundtrip locale, rétrocompatibilité.
`tests/test_json_schema.py` (+2) : exposition `template_vars` dans le JSON.
`tests/test_webhook.py` (+3) : contrat offline (couvert en Zone 2.1).

Total : **+15 tests** (4430 → 4445).

#### Notes de design

- **Option B vs Option A.** Option B = additive, pas de breaking, ce que cette release livre. Option A (breaking : suppression de `message`, `template_vars` obligatoire) reportée à v0.5.0+ quand les 40 checks auront été migrés et que le schéma JSON pourra livrer un v2.
- **Pourquoi 3 pilotes, pas les 40 d'un coup.** Migration mécanique ~500 lignes — possible mais error-prone. Le pattern est documenté via les pilotes ; le reste peut venir incrémentalement (v0.4.2, v0.4.3, …).
- **Dict vide ≠ None.** Choix de `field(default_factory=dict)` plutôt que `Optional[dict]` pour uniformité JSON.

---

### Hardening passe — revue de `bob/formatter.py`

**Fichiers :** `bob/formatter.py`, `bob/i18n.py`, `tests/test_formatter.py`

#### Problème

Une revue post-implémentation de `formatter.py` (analyse ChatGPT externe demandée par l'utilisateur) a relevé quatre problèmes d'API/architecture légitimes sur un module qui s'apprête à devenir un contrat public stable pour les packagers downstream :

1. **Paramètre `lang=` mensonger.** `format_finding(finding, lang=None)` exposait un override de locale qui était un no-op silencieux (`_ = lang` — l'état global `bob.i18n.t()` gagnait toujours). Les appelants externes passant `lang="fr"` obtiendraient toujours la locale du process sans aucune indication. Piège pour les packagers distros qui piperaient les sorties dans leur propre pipeline.
2. **Détection fragile de clé manquante via `startswith("[")`.** `_render_key` retournait `"[key]"` (sentinelle `bob.i18n.t()` pour clés absentes) et l'appelant vérifiait `startswith("[")` pour la détecter. Couple le formatter à une convention `t()` non documentée ; un changement futur de cette sentinelle casserait silencieusement le formatter.
3. **`except (KeyError, TypeError, ValueError)` trop large.** Catcher `TypeError` et `ValueError` masque de vrais bugs Python (e.g. changement d'API `_t()`). Ne devrait swallow que ce qui est vraiment attendu (mismatch de placeholder depuis `str.format`).
4. **Le mot "reproducible" dans la docstring sur-promet** ce que le module peut livrer alors que ~40 checks utilisent encore le chemin legacy `message=`-only.

#### Implémentation

1. **Paramètre `lang=` supprimé** (Option A de la revue). Le réintroduire quand `bob.i18n` deviendra pur (v0.5.x avec l'extraction complète `bob.core`) est préférable à garder une signature mensongère aujourd'hui. La signature pour v0.4.1 est désormais `format_finding(finding) -> str` et `format_deduction(deduction) -> str`.

2. **Nouveau `bob.i18n.try_t(key, **kwargs) -> str | None`** ajouté : détection clean de clé manquante sans parser la sentinelle `"[key]"`. Comportement :
   - Retourne `None` pour les clés absentes (dans la locale active et le fallback EN).
   - Retourne la string rendue en cas de succès.
   - Propage `KeyError` depuis `str.format()` quand un placeholder requis est manquant — responsabilité de l'appelant, pas une dégradation runtime.
   Le legacy `bob.i18n.t()` continue de retourner `"[key]"` pour le reste du codebase qui s'appuie sur ce contrat ; seul `formatter` utilise la nouvelle fonction.

3. **Gestion des exceptions resserrée dans `_try_render`** : plus de catch-all. `try_t` retourne `None` proprement pour les clés manquantes ; `KeyError` depuis `str.format()` (placeholder manquant = bug côté check) propage afin que le bug surface immédiatement au lieu de se dégrader silencieusement vers `finding.message`.

4. **Docstrings réécrites** : "reproducible" → "progressively reconstructible" + une section "Current state (v0.4.1)" précisant exactement ce qui est reproductible aujourd'hui et ce qui ne l'est pas. Le couplage entre `Finding.key` / clé `--explain` / clé i18n / clé de matching JSON (= un ABI textuel) est désormais explicitement reconnu avec un pointeur vers la freeze policy de `bob/explain.py`.

#### Tests

`tests/test_formatter.py` étendu de 10 à 14 tests (+4 dans la nouvelle classe `TestFormatterEdgeCases`) :

| Test | Couverture |
|---|---|
| `test_empty_template_vars_with_placeholder_template_returns_raw` | Edge case : `template_vars` vide + clé dont le template a des placeholders → template brut retourné avec `{placeholders}` littéraux intacts (cohérent avec `i18n.t()`, fait surface le bug visuellement) |
| `test_partial_template_vars_raises_keyerror` | `template_vars` non-vide manquant un placeholder requis → `KeyError` propage (pas de fallback silencieux) |
| `test_mismatched_key_vs_message_uses_key` | Le chemin key gagne quand il résout proprement, même si `message` dit autre chose (la représentation structurée fait autorité une fois populée) |
| `test_empty_finding_message_with_no_key` | Retourne `""` (pas `None`) quand ni key ni message n'est défini — préserve le contrat documenté "retourne toujours une string" |

Décompte total des tests v0.4.1 : **4445 → 4449** (+4 depuis la passe de hardening).

#### Notes de design

- **Pourquoi faire surface `KeyError` au lieu de fallback sur `message`.** Un placeholder manquant signifie que le check a déclaré une key dont le template a besoin d'une variable que le check n'a pas fournie. Utiliser silencieusement `finding.message` masquerait un bug côté check et laisserait les clients sans signal. Lever l'exception force le bug à être visible dans la suite de tests où il devrait être attrapé.
- **Pourquoi `try_t` et pas refactoriser `t()`.** Le legacy `t()` retournant `"[key]"` est utilisé partout dans le codebase pour "afficher mais ne pas crasher". Changer son contrat de retour ricocherait sur 600+ sites d'appel. Ajouter `try_t` comme fonction sœur donne au formatter un signal clé-manquante clean sans perturber la sémantique existante.
- **Pourquoi retirer `lang=` plutôt que le fixer.** Implémenter proprement le switch de locale par appel nécessite de rendre `bob.i18n` réentrant (objet instance plutôt qu'état module-level) — travail qui appartient à v0.5.x avec le refactor complet `bob.core`. Exposer un paramètre aujourd'hui qui ment sur son implémentation est pire que ne pas l'exposer.

---

### Contexte roadmap

Après v0.4.1, le plan Phase 2 est :

| Item | Statut |
|---|---|
| 2.1 `--offline` strict | ✅ fait (vérifié + testé) |
| 2.2 isolation curses (`bob/tui/`) | ✅ fait (cron_ui déplacé) |
| 2.3 découplage core/i18n — Option B (additive) | ✅ fait (3 pilotes + formatter + JSON) |
| 2.3 découplage core/i18n — Option A (breaking) | ⏳ v0.5.0+ |
| Vague 2 schéma (typed ports, `port_resolution`) | ⏳ v0.5.0+ |
| Phase 3 (man pages, debian/, profil AppArmor, SECURITY.md) | ⏳ futur |

---

## [v0.4.0] — 14-05-2026

Phase 1 de la roadmap distro-ready (voir mémoire `project_distro_roadmap`) — cinq contrats d'API publique figés pour que scripts, dashboards et packagers downstream puissent s'appuyer sur un comportement stable entre versions. Aucune nouvelle fonctionnalité, aucun changement breaking — additif uniquement. 4405/4405 tests (+57). Plus un petit correctif UX sur l'affichage du score inchangé.

Cibles de la roadmap par ordre de difficulté :
- AUR / COPR communautaire — viable maintenant
- Debian unstable / Fedora COPR officiel — ~6 mois post-v0.4.0
- Debian main / Fedora main — 12–18 mois minimum (nécessite stabilité soutenue des contrats)

Cette release coche les 5 premières cases de la Phase 1 : codes de retour, fallback locale, contrat de sortie JSON, freeze des clés `--explain`, schéma de plugins. La Phase 2 (découplage architectural : `bob.core` pur, `bob.tui` isolé, `--offline` strict) est la prochaine étape.

---

### Contrat stable — Codes de retour documentés comme API publique

**Fichiers :** `bob/__main__.py`, `bob/cli.py`, `DOCUMENTS/README_TECH.md` (FR/EN)

#### Problème

Les 5 codes de retour (`0`/`1`/`2`/`3`/`4`) étaient définis comme constantes dans `bob/__main__.py` et utilisés de façon cohérente dans `_run()`, mais sans statut formel d'API. Le texte `--help` documentait `0`/`1`/`2`/`3` mais **omettait `4`** (`EXIT_TARGET_MISSED`). README_TECH avait un tableau mais ne promettait pas de stabilité.

Les scripts externes (pipelines CI, wrappers cron, agents de monitoring) ont besoin d'un contrat : la valeur et le sens d'un code ne doit pas dériver entre versions.

#### Implémentation

- Ajout d'un bloc docstring "STABLE PUBLIC API" au-dessus des constantes de codes de retour, énonçant explicitement qu'ils font partie du contrat public de BOB — pas de suppression, pas de glissement sémantique au sein d'une version majeure, ajouts seulement.
- Ajout du `4` manquant dans `--help` (section "EXIT CODES") avec un pointeur vers README_TECH.
- Promotion de la section README_TECH : ajout d'un bloc citation énonçant la promesse de stabilité, tableau étendu avec les noms de constantes (`EXIT_OK`, …), et snippet de code montrant comment les importer programmatiquement.
- Miroir dans README_TECH_FR.

Les 18 tests existants dans `tests/test_exit_codes.py` verrouillent déjà les valeurs et la logique de décision — ils servent désormais d'application du contrat.

#### Notes de design

La décision de code de sortie de `_run()` (target → alerts → warnings → ok) est testée unitairement via `_decide_exit()`, une copie fidèle isolée du pipeline d'audit. C'est le mapping canonique : tout futur changement doit mettre à jour les deux copies et faire évoluer les tests délibérément.

---

### Contrat stable — Détection automatique de la locale via POSIX `$LANG`

**Fichiers :** `bob/i18n.py`, `bob/cli.py`, `tests/conftest.py`, `tests/test_i18n.py`, `tests/test_cli.py`, `bob/cli.py` (--help), `DOCUMENTS/README_TECH.md` (FR/EN)

#### Problème

L'interface de BOB par défaut était l'anglais sauf si `--french` ou `--lang=fr` était passé explicitement. Tout autre outil Unix (`man`, `git`, `apt`, `gcc`, …) honore automatiquement `$LANG` / `$LC_*`. Un utilisateur français tapant `sudo bob` obtenait l'anglais ; surprenant et non-conforme aux attentes POSIX.

Pour le packaging distro, c'est encore plus important : un paquet Debian livrant BOB doit s'intégrer harmonieusement avec la locale système. Un utilisateur avec `LANG=fr_FR.UTF-8` doit obtenir une sortie française sans gymnastique de flags.

#### Implémentation

Nouvelle fonction `bob.i18n.detect_system_lang() -> str` :

```python
def detect_system_lang() -> str:
    for var in ("LC_ALL", "LC_MESSAGES", "LANG"):
        value = os.environ.get(var, "").strip()
        if not value or value in ("C", "POSIX", "C.UTF-8", "C.utf8"):
            continue
        prefix = value.split(".", 1)[0].split("@", 1)[0]
        lang = prefix.split("_", 1)[0].lower()
        if lang in SUPPORTED_LANGS:
            return lang
        return DEFAULT_LANG
    return DEFAULT_LANG
```

L'ordre de probe correspond à POSIX (`LC_ALL` prime sur `LC_MESSAGES` qui prime sur `LANG`). Les valeurs vides retombent sur le candidat suivant. `C` / `POSIX` / `C.UTF-8` / langues non supportées → fallback sur `DEFAULT_LANG = "en"`.

`bob.cli.parse_args()` suit désormais si l'utilisateur a passé `--lang=` / `--french` via un flag local `lang_explicit`. Après le parsing argv, si le flag est encore `False`, `config.lang = detect_system_lang()`. Les flags explicites priment toujours — la détection est un défaut, pas un override.

`tests/conftest.py` (nouveau) : une fixture autouse définit `LC_ALL=C`/`LANG=C` avant chaque test, afin que les défauts CLI dépendants de la locale se résolvent prévisiblement, indépendamment de la locale hôte du dev. Les tests qui ont besoin d'une locale spécifique la définissent explicitement avec `monkeypatch.setenv()`.

#### Tests

- 12 nouveaux tests dans la classe `TestDetectSystemLang` : env vide, `C`, `POSIX`, `C.UTF-8`, `fr_FR.UTF-8`, `fr_BE`, `fr_FR@euro`, `en_US.UTF-8`, non supportés `ja_JP`/`de_DE`/`es_ES`/`zh_CN`, override par `LC_ALL`, override par `LC_MESSAGES`, `LC_ALL` vide retombe.
- 4 tests d'intégration dans `tests/test_cli.py` : `--french` override la locale système, `--lang=en` override la locale système, default utilise `fr` quand la locale système est française, default utilise `en` quand `LANG=C`.

#### Notes de design

La décision de défaut sur la locale système (au lieu de toujours `en`) est une amélioration UX, pas un breaking change pour un contrat documenté — `--lang=en` continue de fonctionner et force l'anglais explicitement. Le changement est documenté dans `--help` ("default: detected from $LANG, fallback en") et dans les deux variantes README_TECH. Les CI/scripts existants qui ne définissent pas `LC_ALL` ne voient aucun changement parce que `LANG=C` retombe sur `en`.

---

### Contrat stable — Schéma de sortie JSON documenté + champ `key` exposé

**Fichiers :** `bob/json_output.py`, `tests/test_json_schema.py` (nouveau), `DOCUMENTS/README_TECH.md` (FR/EN)

#### Problème

La sortie `--json` avait `"schema_version": "1"` depuis v0.2.x mais sans contrat formel : les clés top-level pouvaient disparaître ou être renommées sans préavis, le schéma n'avait aucun test d'enforcement, et les clients devaient matcher les findings via les chaînes `message` / `reason` localisées (qui diffèrent entre `en` et `fr`).

Pour l'adoption distro c'est un blocage : un dashboard packagé Debian parsant la sortie BOB ne peut pas être attendu de switcher la logique de matching par locale, ni survivre à une dérive silencieuse du schéma entre releases BOB.

#### Implémentation

Ajout d'un docstring de stabilité en tête de `bob/json_output.py` formalisant les règles :

> - Les clés top-level ne disparaissent jamais, ne sont jamais renommées, ne changent jamais de sémantique au sein d'une même version majeure de `schema_version`.
> - De nouvelles clés top-level PEUVENT être ajoutées dans n'importe quelle release ; les clients doivent ignorer les clés inconnues.
> - Les dicts imbriqués suivent la même règle.
> - Les changements breaking incrémentent `schema_version` à un nouveau majeur (`"2"`, `"3"`…).

Deux nouvelles constantes module-level rendent le contrat testable :

```python
SCHEMA_V1_REQUIRED_KEYS = frozenset({
    "schema_version", "version", "host", "timestamp", "score", "score_max",
    "risk", "network_context", "public_ip", "alerts", "warnings",
    "deductions", "domain_scores",
})
SCHEMA_V1_FULL_KEYS = frozenset({
    "findings", "services", "open_ports", "firewall_stack",
    "hardening", "ipv6",
})
```

Ajout de `"key": d.key` à chaque entrée `deductions[]` et `"key": f.key` à chaque entrée `findings[]`. Ce sont des clés i18n stables en notation pointée (`firewall.logging_off`, `ssh.password_auth`, …) qui ne changent jamais entre locales et ne sont jamais renommées sans entrée d'alias — les clients doivent matcher sur `key`, pas sur `reason`/`message`.

`DOCUMENTS/README_TECH.md` (et FR) gagnent une section complète "Schéma de sortie JSON" : promesse de stabilité citée, tableau complet des clés top-level avec types et descriptions, structure de `deductions[]` / `domain_scores` / clés full-mode, exemple de matching indépendant de la locale avec `jq`.

#### Tests

`tests/test_json_schema.py` (nouveau, 15 tests, 4 classes) :

- `TestSchemaVersion` — schema_version est une string, actuellement `"1"`.
- `TestRequiredKeysAlwaysPresent` — clés requises en mode short et full, aucune clé full-only ne fuit en mode short.
- `TestFieldTypes` — `score`/`score_max`/`alerts`/`warnings` sont int, `risk` est string, `timestamp` est ISO 8601.
- `TestStableKeysExposed` — chaque deduction et finding a un champ `key`, format dotted-path.
- `TestDomainScoresStructure` — `domain_scores` est un dict-of-dicts avec `score` (int) et `label` (str).

#### Notes de design

L'exposition du champ `key` est la fondation du découplage architectural Phase 2 : une fois `Finding.message` découplé de `_t()` (planifié dans la prochaine phase), la sortie JSON deviendra entièrement indépendante de la locale — les clients pourront formater eux-mêmes les messages depuis les clés.

---

### Contrat stable — Alias map `--explain` + politique de freeze

**Fichiers :** `bob/explain.py`, `tests/test_explain.py`

#### Problème

Les 112 clés `--explain` (e.g. `ssh.password_auth`, `firewall.logging_off`, `kernel_hardening.aslr_disabled`) sont aussi utilisées comme `Finding.key` et `Deduction.key` — elles forment un namespace public sur lequel scripts et dashboards matchent. Renommer une clé était un breaking change silencieux.

#### Implémentation

Ajout d'une section explicite "STABLE PUBLIC API — `--explain` KEY FREEZE POLICY" au docstring du module, énonçant quatre règles : pas de suppression, pas de glissement sémantique, les renommages passent par `EXPLAIN_KEY_ALIASES`, ajouts libres.

Introduction de `EXPLAIN_KEY_ALIASES: dict[str, str]` comme mécanisme de migration pour les renommages. Vide pour l'instant — aucune clé n'a encore été renommée. La map existe pour qu'un futur renommage ait un chemin documenté et testé : ajouter `"old_name": "new_name"` ici et les clients appelant `bob --explain old_name` (ou matchant `Finding.key == "old_name"` en JSON) continuent de fonctionner indéfiniment.

`normalize_key()` étendue pour consulter la map d'alias après le strip des segments de chemin :

```python
def normalize_key(key: str) -> str:
    m = _NORMALIZE_RE.match(key)
    if m:
        key = f"{m.group(1)}.{m.group(2)}"
    return EXPLAIN_KEY_ALIASES.get(key, key)
```

#### Tests

6 nouveaux tests dans `tests/test_explain.py` :

- `TestExplainKeyAliases` (5 tests) : la map d'alias est un dict, les cibles d'alias sont des clés canoniques valides, les clés d'alias ne sont PAS dans le set canonique (pas d'overlap), `normalize_key()` résout les alias, passthrough sans alias.
- `TestExplainKeyFreezePolicy` (1 test) : un sous-ensemble figé de 16 clés load-bearing (`ssh.password_auth`, `ssh.permit_root_login`, `firewall.logging_off`, `kernel_hardening.aslr_disabled`, …) doit toujours être dans `EXPLAIN_KEYS` — l'échec pointe soit vers leur restauration, soit vers l'enregistrement d'un alias.

#### Notes de design

La politique de freeze est intentionnellement par clé (pas par groupe) : les groupes peuvent être réorganisés dans `_EXPLAIN_GROUPS` sans casser de contrat, seules les clés individuelles sont sticky.

---

### Contrat stable — JSON Schema formel pour les plugins services

**Fichiers :** `bob/data/schemas/service.schema.json` (nouveau), `bob/data/schemas/services-list.schema.json` (nouveau), `pyproject.toml`, `bob/registry.py`, `tests/test_services_schema.py` (nouveau), `DOCUMENTS/README_TECH.md` (FR/EN)

#### Problème

Les définitions de services (`bob/data/services.json` + plugins utilisateur dans `~/.config/bob/services.d/`) avaient un validateur fait main dans `Service.from_dict()` (Python uniquement, distribué sur 36 lignes). Les packagers de distro et auteurs de plugins n'avaient aucun contrat machine-readable : les règles (champs requis, regex pour les ports, enum pour le risk, règles d'identifier pour `config_key`) devaient être reverse-engineerées depuis le code Python ou par essai-erreur.

#### Implémentation

Deux fichiers JSON Schema Draft 2020-12 :

- **`service.schema.json`** décrit une seule entrée service (le dict passé à `Service.from_dict()`) :
  - `additionalProperties: false` (aucun champ inconnu)
  - 7 champs requis (`id`, `label`, `packages`, `services`, `ports`, `risk`, `config_key`)
  - Patterns stricts : `id` est `^[a-zA-Z][a-zA-Z0-9_-]*$`, ports `^[1-9][0-9]{0,4}/(tcp|udp)$`, `config_key` est un identifier Python
  - `risk` est enum `{low, medium, high, critical}`
  - Conditionnel via `allOf` / `if/then` : quand `config_key="fixed"`, `ports` doit avoir `minItems: 1`
  - `detection` (optionnel) avec arrays `binary` / `snap` / `config_files`
- **`services-list.schema.json`** wraps la forme tableau (le fichier `services.json` entier ou un fichier plugin utilisateur).

Schémas livrés via `package_data` afin qu'ils soient disponibles à `bob/data/schemas/*.json` après pip install — n'importe quel tooling externe (`check-jsonschema`, `ajv`, plugins d'IDE) peut valider les plugins utilisateur.

Le validateur Python dans `Service.from_dict()` reste la source de vérité au runtime — **zéro dépendance runtime ajoutée**. Le JSON Schema le reflète pour le tooling externe.

Le docstring de la classe `bob/registry.py` `Service` pointe désormais vers le fichier schéma comme contrat formel.

`DOCUMENTS/README_TECH.md` (et FR) gagne une sous-section "Schéma de plugin de service" avec un exemple complet et l'explication des champs requis vs optionnels. La note antérieure sur la résolution de `Path.home()` vers `/root` est aussi mise à jour pour refléter le fix v0.3.6 `get_user_home()`.

#### Tests

`tests/test_services_schema.py` (nouveau, 20 tests, 5 classes) :

- `TestSchemasAreWellFormed` — les schémas passent l'auto-validation Draft 2020-12, ont `$id`/`title` propres.
- `TestBundledServicesMatchSchema` — `services.json` bundled valide entrée par entrée, IDs uniques.
- `TestValidPluginSamples` — 3 plugins valides échantillons (minimal fixed, avec block detection, user config_key).
- `TestInvalidPluginSamples` — 8 cas de rejet (champ requis manquant, risk invalide, port malformé, port 0, port > 65535 via Python, champ inconnu, fixed sans ports, ID avec espaces, string binary vide).
- `TestSchemaPythonParity` — ce que le schema accepte est aussi accepté par `Service.from_dict()`, ce qui échoue Python est aussi attrapé par le schema.

`jsonschema` est une dépendance test-only, pas runtime — utilise `pytest.importorskip` pour que le fichier de tests skippe simplement sur les systèmes sans cette installation.

#### Notes de design

La contrainte de plage de ports (1–65535) est appliquée par Python uniquement — le regex du schema permet 1–99999 pour la simplicité. Documenté dans la `description` du schema. Compromis acceptable : le test de parité `Service.from_dict()` garantit que les ports invalides sont rejetés au runtime ; les linters externes obtiennent un warning "good enough" qui attrape les erreurs évidentes (port 0, décimaux, chaînes non numériques).

Le champ `binary` accepte à la fois des noms de binaires (résolus via `$PATH`) et des chemins absolus — le `services.json` bundled utilise les deux formes (e.g. `"in.telnetd"` pour telnet, `"/usr/sbin/postfix"` serait aussi valide).

---

### Hardening — Schéma de plugin réécrit après revue externe

**Fichiers :** `bob/data/schemas/service.schema.json`, `bob/data/schemas/services-list.schema.json`, `bob/data/schemas/plugin-file.schema.json` (nouveau), `bob/data/services.json`, `bob/registry.py`, `tests/test_services_schema.py`

#### Problème

Une revue externe (analyse ChatGPT proposée par l'utilisateur) a relevé 10 points sur le JSON Schema introduit plus tôt dans cette release. Cinq d'entre eux étaient de vraies fuites de contrat qui auraient induit en erreur les packagers de distros et linters externes ; cette section les corrige. Les cinq autres (`ports: [{port,proto}]` typé, objet `port_resolution` remplaçant le mix enum/identifier de `config_key`, `packages: {apt:[],dnf:[]}` multi-PM, union typée pour `binary`, wrapper plugin avec metadata) sont des breaking changes reportés au schéma v2 (planifié pour v0.5.0).

Les cinq corrigés dans cette release :

1. **Promesses des descriptions que le schéma ne valide pas.** La version précédente affirmait « must be unique across all loaded services » et « mirrors `Service.from_dict()` validation » — les deux étaient mensongers. JSON Schema ne peut pas valider l'unicité cross-document, et le schéma ne reflétait qu'un *sous-ensemble* de la validation Python (notamment manquait le check des reserved keywords et la plage stricte 1–65535 pour les ports).
2. **Regex port délibérément lâche** (`^[1-9][0-9]{0,4}/(tcp|udp)$` permettait `99999/tcp`). Un plugin schema-valide pouvait échouer au runtime — cassait le contrat « schema-valid == application-valid ».
3. **Pas de factorisation `$defs`** — patterns string répétés dispersés dans les properties.
4. **Contraintes métier manquantes** — `config_key="auto"` sans `config_files` était valide, un `detection: {}` vide était valide, et un plugin avec `packages: []`, `services: []`, sans `detection` était valide (et indétectable au runtime).
5. **Pas de `schema_version` dans les fichiers plugin** — impossible de gater proprement les futures migrations de schéma.
6. **`$id` pointait vers `github.com/.../blob/main/...`** — URL instable (page HTML, branch-dépendante, pas raw, pas versionnée).

#### Implémentation

**`service.schema.json`** réécrit avec :

- **Bloc `$defs`** factorisant 6 sous-schémas réutilisables : `Identifier`, `PythonIdentifier`, `PackageName`, `SystemdUnit`, `PortProto`, `BinaryRef`, `AbsolutePath`. Chacun porte une description explicite annonçant les changements planifiés en v2 (ports typés, union binary typée).
- **Regex port stricte** `^(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})/(tcp|udp)$` validant exactement 1–65535. Schema-valide égale désormais Python-valide.
- **Description de scope claire** énonçant quels invariants le schéma applique vs quels invariants restent runtime-only (unicité cross-service, exclusion des reserved keywords Python).
- **3 contraintes métier `allOf`** via `if/then` et `anyOf` :
  1. `config_key="fixed"` requiert `ports.minItems: 1` (déjà présent).
  2. `config_key="auto"` requiert `detection.config_files.minItems: 1` (nouveau — sans ça, l'auto-détection n'a rien à parser).
  3. Le service doit être détectable : au moins un parmi `packages`, `services`, ou `detection.{binary|snap}` non-vide (nouveau — empêche de charger des services invisibles).
- **`detection.minProperties: 1`** — blocs detection vides (`detection: {}`) rejetés.
- **`$id` versionné** pointant vers `raw.githubusercontent.com/.../v0.4.0/...` — stable, raw, pin de version.

**`plugin-file.schema.json`** (nouveau) décrit les deux formes acceptées pour `~/.config/bob/services.d/*.json` :

```json
[ { ...service... }, { ... } ]
```

…ou :

```json
{
  "schema_version": 1,
  "services": [ { ...service... } ]
}
```

Le wrapper existe pour que les futures migrations de schéma (v2 ports typés, etc.) puissent être gatées explicitement via `schema_version`. Aujourd'hui seul `schema_version: 1` est accepté ; les champs réservés comme `metadata` / `disabled` sont rejetés aujourd'hui et marqués pour les versions futures.

**`bob/registry.py`** : nouveau helper `_extract_plugin_entries(raw, plugin_name) -> list | None` consomme les deux formes. La constante `_CURRENT_PLUGIN_SCHEMA_VERSION = 1` filtre : les versions supérieures sont rejetées avec un warning « upgrade BOB or downgrade the plugin » donnant un hint clair plutôt qu'un demi-chargement silencieux. Versions inférieures ou non-entières aussi rejetées. Le chemin legacy raw-array est inchangé — rétrocompatibilité préservée.

**`bob/data/services.json`** : 4 services bundled avaient un bloc `detection: {binary: [], snap: [], config_files: []}` qui n'apportait aucun signal. Supprimé entièrement. `postgresql` et `syncthing` avaient `config_key="auto"` sans `config_files` (fonctionnellement équivalent à `fixed`) — migrés à `config_key="fixed"` pour matcher la réalité.

#### Tests

`tests/test_services_schema.py` étendu de 20 à 42 tests (+22) :

- `TestInvalidPluginSamples` mis à jour : `test_port_above_65535_rejected_by_schema` (plus seulement Python), plus tests aux bornes `test_port_65535_accepted` / `test_port_65536_rejected`.
- `TestBusinessConstraints` (nouveau, 7 tests) : `auto` sans `config_files` rejeté, `auto` avec array vide rejeté, `auto` avec paths accepté, service indétectable rejeté, détection binary-only / snap-only acceptée, `detection: {}` vide rejetée.
- `TestPluginFileWrapper` (nouveau, 6 tests) : array legacy accepté, wrapped v1 accepté, `schema_version` manquant rejeté, `services` manquant rejeté, v2 actuellement rejetée, champs extras rejetés.
- `TestRegistryAcceptsBothShapes` (nouveau, 7 tests) : `_extract_plugin_entries` Python accepte les deux formes, rejette unknown / zero / non-int / services manquants, rejette non-array/non-dict.

`jsonschema.RefResolver` utilisé pour la résolution cross-file `$ref` (conservé pour compat avec jsonschema 4.10+ ; le `referencing` Registry moderne de 4.18+ marcherait aussi).

#### Notes de design

- **Schéma v2 reporté délibérément.** Refactoriser `ports: ["22/tcp"]` → `ports: [{port: 22, proto: "tcp"}]` impacte `bob/data/services.json` (32 services), la dataclass `Service`, `_PORT_RE`, chaque check qui itère sur `service.ports`, plus d'importantes réécritures de fixtures de tests. Ce travail appartient à v0.5.0 avec documentation de migration explicite, pas dans cette release.
- **Le wrapper pré-empte le problème v2.** Aujourd'hui `schema_version: 1` est la seule valeur acceptée, mais le champ existe dans le format de fichier dès maintenant. Quand v2 sortira, les fichiers plugin déclarant `schema_version: 2` obtiennent le nouveau validateur ; les plugins v1 continuent de fonctionner via un chemin de compat.
- **Les blocs `detection` vides étaient silencieusement cassés.** Certains services bundled les portaient comme boilerplate ; les retirer fait remonter le vrai signal de détection et évite de futurs copier-coller de config morte.

---

### Hardening passe #2 — descriptions schémas, fixtures tests, compat RefResolver

**Fichiers :** `bob/data/schemas/services-list.schema.json`, `bob/data/schemas/plugin-file.schema.json`, `tests/conftest.py`, `tests/test_json_schema.py`, `tests/test_services_schema.py`

#### Problème

Une seconde passe de revue externe sur les schémas et fichiers de tests fraîchement durcis a fait remonter une plus petite série de problèmes légitimes — aucun structurel cette fois, mais à corriger avant de figer le contrat v0.4.0 :

1. **`services-list.schema.json`** : un tableau vide `[]` était structurellement valide (pas de `minItems`). Un utilisateur créant un fichier plugin et oubliant d'ajouter des entrées obtenait un fichier silencieusement chargé avec zéro service.
2. **`plugin-file.schema.json`** : la description utilisait un wording "schema_version: 1 fallback implicite" qui n'était pas reflété dans le schéma lui-même, et n'expliquait pas *pourquoi* `maximum: 1` est délibéré ou *pourquoi* `additionalProperties: false` rejette les champs mêmes que la description appelle "réservés". Risque : un packager lit la description et pense que le schéma déraille.
3. **`tests/conftest.py`** : `import os` inutilisé (warning pyflakes), et le docstring promettait plus que la fixture n'apporte (set juste les variables d'environnement, n'appelle pas `setlocale()` pour les consommateurs libc/ICU).
4. **`tests/test_json_schema.py`** : injection massive de `MagicMock` dans les fixtures — un attribut renommé dans les types réels passés à `build_json_data` (e.g. `sys_info.fqdn` au lieu de `sys_info.hostname`) passait silencieusement (les mocks inventent les attributs au moment de l'accès). Le validateur de timestamp était un check de substring (`"T" in ts`) qui accepte plein de chaînes non-ISO. Le contrat avait une seule source (les constantes de production `SCHEMA_V1_REQUIRED_KEYS` / `SCHEMA_V1_FULL_KEYS`), donc un edit malheureux des constantes laissait les tests tautologiques.
5. **`tests/test_services_schema.py`** : `RefResolver` est déprécié dans jsonschema ≥ 4.18 (on est sur 4.10 aujourd'hui ; les runners CI sur images plus récentes émettraient `DeprecationWarning`). Les quatre fixtures `validator` par classe dupliquaient le même one-liner. Le check duplicate-id utilisait `ids.count(x)` par élément (O(n²)). Plusieurs `assert errors` ne pinaient pas quel champ l'erreur concerne — une régression ailleurs dans le schéma pouvait masquer un test manquant.

#### Implémentation

**Schémas :**

- `services-list.schema.json` : ajout `"minItems": 1`. Description réécrite pour clarifier qu'il s'agit de la forme canonique de la liste bundled et pour rediriger les utilisateurs vers `plugin-file.schema.json` pour les nouveaux fichiers plugin. Note explicite que l'unicité cross-service de `id` est runtime-only (cohérent avec la clause SCOPE de `service.schema.json`).
- `plugin-file.schema.json` : le titre gagne le suffixe `— schema v1` pour rendre le versioning explicite. Description top-level restructurée en trois sections :
  - **Pourquoi `maximum: 1`** : chaque bump majeur de schéma livre son PROPRE `plugin-file.schema.json` à un NOUVEL `$id`. Un fichier plugin v2 DOIT être validé contre le schéma v2, pas celui-ci.
  - **Pourquoi `additionalProperties: false` rejette les champs "réservés"** : rejeter aujourd'hui empêche les collisions avec le sens que v2/v3 leur donneront.
  - **Fallback runtime `[…] → schema_version: 1`** : explicitement noté comme une convenance d'`_extract_plugin_entries`, PAS une règle du schéma.

**conftest.py** : retiré l'import `os` inutilisé. Docstring énonce explicitement "only sets process environment variables. It does NOT call `setlocale()`" et justifie le triple explicite `LC_ALL`/`LC_MESSAGES`/`LANG` (la précédence POSIX rend les deux derniers redondants quand `LC_ALL` est défini, mais le triple explicite documente l'intention et est robuste contre du code aval qui sonderait directement n'importe quelle variable).

**test_json_schema.py** : réécriture complète des fixtures :
- `MagicMock` remplacés par des instances réelles `SystemInfo`, `PortsSnapshot`, `FirewallStackSnapshot`, `NetworkContextSnapshot`, `CheckResult`. Un attribut renommé dans `bob.json_output.build_json_data` lève désormais `AttributeError` au lieu d'être auto-mocké.
- Le test de timestamp utilise `datetime.fromisoformat(ts)` (ISO 8601 strict) et assert `tzinfo is not None`.
- Source du contrat dupliquée : un set hard-codé `EXPECTED_REQUIRED_KEYS_V1` / `EXPECTED_FULL_KEYS_V1` dans le fichier de test matche contre les constantes de production, donc un edit d'un côté sans l'autre est attrapé (`test_constants_match_expected_set`).
- Nouveau `test_short_mode_strict_set` rejette les clés inattendues qui fuiraient en mode short — les ajouts additifs doivent être explicites (déplacer en full mode ou bumper schema_version).
- Création du engine soulevée dans une fixture pytest (était dupliquée 12+ fois via des appels `_make_engine()`).

**test_services_schema.py :**
- Nouveau helper `_make_resolved_validator(root, extra_schemas)` essaie le path moderne `referencing.Registry` d'abord (jsonschema ≥ 4.18) et retombe sur le `RefResolver` legacy (4.10–4.17). Point de migration unique quand la branche legacy disparaîtra.
- Fixture module-scope `service_validator` remplace quatre duplications par classe ; les fixtures par classe `validator` deviennent des delegates d'une ligne.
- `test_bundled_services_have_unique_ids` passe à `Counter` (O(n)).
- Asserts ciblés via `e.absolute_path` au lieu de matching de substring sur le message, dans les tests les plus informatifs : `test_invalid_port_format`, `test_port_zero_rejected`, `test_port_above_65535_rejected_by_schema`, `test_id_with_spaces_rejected`, `test_empty_binary_string_rejected`. `absolute_path` est stable entre versions de jsonschema ; `e.message` ne l'est pas.

#### Tests

Total **4430/4430** (était 4427 avant cette passe — net +3, tous defense-in-depth) :
- `test_json_schema.py` : 15 → 17 (+`test_short_mode_strict_set`, +`test_constants_match_expected_set`).
- `test_services_schema.py` : 42 → 43 (+`test_services_list_rejects_empty_array` — vérifie le nouveau `minItems: 1`).
- Tous les tests existants passent après le refactor MagicMock-vers-réel — preuve que le code de production accède exactement aux attributs que les dataclasses exposent (aucune divergence cachée).

#### Notes de design

- **Pourquoi deux passes de hardening au lieu d'une release proprement factorisée.** Chaque passe a été déclenchée par une revue externe distincte (ChatGPT) sur les fichiers sélectionnés par l'utilisateur dans son IDE. Les séparer dans le changelog préserve la trace "ce qui a été manqué la première fois", utile pour les postmortems et pour comprendre le resserrement itératif.
- **`assert errors` vs `assert errors[i].absolute_path == [...]`** — gardé `assert errors` sur les cas triviaux (e.g. `test_unknown_field_rejected`, `test_fixed_without_ports_rejected`) où le mode de défaillance est "n'importe quelle erreur". Resserré uniquement sur les tests où plusieurs violations distinctes pourraient se masquer mutuellement.
- **Defense in depth via liste de clés dupliquée.** Le set `EXPECTED_REQUIRED_KEYS_V1` dans le fichier de test est intentionnellement une copie de `SCHEMA_V1_REQUIRED_KEYS`. Le test `test_constants_match_expected_set` est le filet de sécurité : un edit non-intentionnel de la constante de production fait passer le test au rouge, forçant l'éditeur à acquitter le changement de contrat.

---

### Bonus UX — Suffixe `= N` redondant sur score inchangé supprimé

**Fichiers :** `bob/display.py`, `tests/test_min_level.py`

#### Problème

Le test terrain sur so6desktop a montré :

```
║  Score de sécurité : 8/10  = 8                                               ║
```

Le `= 8` était un vestige d'un fix v0.3.0 ("score delta orphan arrow: stable score shows = N instead of bare →") — l'intention originelle était d'éviter une `→` orpheline quand le score était inchangé, mais la forme `= N` finit redondante : le score `8/10` est déjà deux caractères avant sur la même ligne.

#### Implémentation

Dans `bob/display.py:print_audit_summary()`, la branche `delta == 0` est supprimée entièrement :

```python
score_str = f"{score}/10"
if prev_score is not None:
    delta = score - prev_score
    if delta > 0:
        score_str += f"  {_c.green}↑ +{delta}{_c.reset}"
    elif delta < 0:
        score_str += f"  {_c.yellow}↓ {delta}{_c.reset}"
    # delta == 0: score unchanged, no annotation needed
```

`tests/test_min_level.py:TestScoreTrend::test_stable_shows_equal` renommé `test_stable_shows_no_annotation` et inversé : assert désormais qu'aucune flèche `↑`/`↓` n'apparaît et que la valeur est exactement `"7/10"` (sans suffixe).

---

### Récap tests — 4430/4430 (+82)

| Fichier de test | Classe | Nouveaux | Existants |
|---|---|----:|----:|
| `tests/test_exit_codes.py` | (existants) | 0 | 18 |
| `tests/test_i18n.py` | `TestDetectSystemLang` | +12 | — |
| `tests/test_cli.py` | `TestParse::test_*_locale` | +4 | — |
| `tests/test_json_schema.py` (nouveau) | 4 classes | +17 | — |
| `tests/test_explain.py` | `TestExplainKeyAliases`, `TestExplainKeyFreezePolicy` | +6 | — |
| `tests/test_services_schema.py` (nouveau) | 9 classes | +43 | — |
| `tests/test_min_level.py` | `TestScoreTrend::test_stable_shows_no_annotation` | renommé | — |
| `tests/conftest.py` (nouveau) | fixture autouse force `LANG=C` | — | — |

Notes sur la trajectoire de ces décomptes pendant le développement de v0.4.0 :
- `test_services_schema.py` : 20 (initial) → 42 (passe de hardening post-revue #1) → 43 (passe #2 a ajouté `test_services_list_rejects_empty_array` pour le nouveau `minItems: 1`).
- `test_json_schema.py` : 15 (initial) → 17 (passe #2 a ajouté `test_short_mode_strict_set` et `test_constants_match_expected_set` comme defense-in-depth contre les dérives silencieuses du contrat).

### Validation terrain

Audit bout en bout sur so6desktop (Linux Mint 22.3) confirme :
- Bannière v0.4.0 correctement affichée
- Locale auto-détectée comme français via `$LANG=fr_FR.UTF-8`
- Toutes les sections rendues correctement ; journalisation UFW affichée (UFW actif), link-local IPv6 correctement classés, plugins/profils chargés depuis `/home/so6/.config/bob/`
- Score 8/10, delta tracé depuis l'audit précédent, ligne "Score inchangé" affichée sans suffixe redondant `= 8`
- 4405 tests verts, pyflakes propre (un seul `# noqa: F401` intentionnel)

---

## [v0.3.6] — 09-05-2026

Passe de code review suite à un audit approfondi du code. Aucune nouvelle fonctionnalité, aucun changement de comportement, aucun nouveau test — uniquement des corrections de bugs, du nettoyage d'hygiène et des améliorations de cohérence. Huit correctifs liés couvrant la résolution de chemin sudo-aware, la couverture des plages privées IPv6, la sémantique du check SSH, le rendu de section UFW, la compatibilité legacy cron, le placement des sub-checks, les imports morts et les clés de locales mortes. 4348/4348 tests.

---

### Correctif — `Path.home()` retourne `/root` sous sudo (+ helper chown pour les fichiers écrits sous sudo)

**Fichiers :** `bob/config.py`, `bob/recurrence.py`, `bob/history.py`, `bob/registry.py`, `bob/compare.py`, `bob/profiles.py`, `bob/plugin_checks.py`, `bob/ignore.py`, `bob/sysinfo.py`

#### Problème

Sept modules calculaient des constantes de chemin au niveau du module avec `Path.home()` :

```python
_DEFAULT_CONFIG_DIR = Path.home() / ".config" / "bob"        # config.py
_PLUGIN_DIR        = Path.home() / ".config" / "bob" / "services.d"  # registry.py
_USER_PROFILES_DIR = Path.home() / ".config" / "bob" / "profiles"    # profiles.py
# ... et 4 autres
```

`Path.home()` consulte `$HOME`. Sous `sudo`, `$HOME` vaut typiquement `/root` (préservé à travers la frontière sudo sur la plupart des distros). Résultat : BOB cherchait les profils utilisateur dans `/root/.config/bob/profiles/`, les plugins dans `/root/.config/bob/services.d/`, la baseline dans `/root/.config/bob/last_baseline.json`, etc. — sans jamais lire la configuration de l'utilisateur invoquant.

Un helper correct existait déjà : `bob.sysinfo.get_user_home()` honore `SUDO_USER` et retombe sur `Path.home()` :

```python
def get_user_home() -> Path:
    sudo_user = os.environ.get("SUDO_USER", "")
    if sudo_user and re.match(r"^[a-zA-Z0-9_.-]{1,256}$", sudo_user):
        import pwd
        try:
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            ...
    return Path.home()
```

…mais il n'était utilisé qu'à deux endroits (`sysinfo.py:91`, `manage_logs.py:155`).

#### Implémentation

Les sept modules importent `get_user_home` depuis `bob.sysinfo` et remplacent `Path.home()` par `get_user_home()` dans les constantes concernées. La résolution se fait toujours à l'import (préserve la surface d'API existante — beaucoup d'appelants référencent ces constantes directement), mais pointe désormais correctement sur le home de l'utilisateur invoquant. `bob/ignore.py` avait sa propre logique `SUDO_USER` dupliquée — remplacée par un appel au helper partagé.

#### Correctif compagnon — helper `chown_to_sudo_user(path)`

Pointer la config vers `~/.config/bob/` sous sudo n'est que la moitié du correctif : les écritures se font en root, donc chaque fichier nouvellement créé finit propriété de root. Lors d'une session non-sudo ultérieure, l'utilisateur ne peut plus lire ni éditer sa propre config.

Un nouveau helper `bob.sysinfo.chown_to_sudo_user(path)` chown un chemin vers l'uid/gid de `SUDO_USER`. No-op quand :
- `SUDO_USER` n'est pas défini (login root réel ou utilisateur normal)
- `SUDO_USER` échoue la regex de validation
- L'appel chown lui-même échoue (best-effort — le helper avale `OSError`)

Appliqué à chaque site d'écriture de config utilisateur :
- `bob/config.py` — après `mkdir(parents=True, mode=0o700)` et après chaque `replace` atomique (UserConfig + EmailStore)
- `bob/compare.py` — après `mkdir(parents=True)` et après `tmp.replace(dest)` pour la baseline
- `bob/recurrence.py` — après `mkdir(parents=True)` et après `tmp.replace(dest)`
- `bob/history.py` — après `mkdir(parents=True)`, après le premier `open("a")` si le fichier n'existait pas, et après chaque rotation `os.replace`
- `bob/ignore.py` — après `mkdir(parents=True)` et après `write_text`

#### Correctif compagnon — gardes `PermissionError` sur les lectures de plugins

Les installations existantes peuvent avoir un répertoire `~/.config/bob/services.d/` ou `checks.d/` créé par root depuis un run sudo antérieur au fix. Après le fix, la session utilisateur tente de lire ces répertoires et obtient `PermissionError`. Trois sites de lecture obtiennent une garde pour que l'audit retombe gracieusement sur « aucun plugin chargé » au lieu de crasher :

- `bob/registry.py:_load_plugins` — `_PLUGIN_DIR.is_dir()` et `_PLUGIN_DIR.glob()` enveloppés dans try/except PermissionError
- `bob/plugin_checks.py:load_plugin_checks` — même pattern sur `_PLUGIN_CHECKS_DIR`
- `bob/profiles.py:_resolve_path` — `candidate.is_file()` enveloppé par dossier, retombe sur le suivant

#### Notes de design

- Le helper valide `SUDO_USER` contre une regex stricte avant la lecture via `pwd.getpwnam` — défense contre l'injection de variable d'environnement.
- Pas de risque d'import circulaire : `bob.sysinfo` n'importe que la stdlib au niveau module (`bob.report` et `bob.output` sont importés en lazy dans `collect_system_info()`).
- Le fallback `Path.home()` à l'intérieur de `get_user_home()` préserve le comportement quand BOB est invoqué hors contexte sudo.
- `chown_to_sudo_user` est best-effort — les échecs sont loggés en debug et ne se propagent jamais. Le fallback (fichier propriété de root) est le comportement antérieur au fix, donc le mode de défaillance équivaut au comportement précédent.

#### Migration pour utilisateurs existants

Les utilisateurs ayant lancé une version pré-fix de BOB sous sudo peuvent avoir un `~/.config/bob/` propriété de root. Pour restaurer l'accès :

```
sudo chown -R "$USER:$USER" ~/.config/bob/
```

Les futurs runs sudo chowneront automatiquement les nouveaux fichiers via le helper.

---

### Correctif — `AllowTcpForwarding local` signalé comme avertissement

**Fichiers :** `bob/checks/ssh.py:553`

#### Problème

Le check SSH n'acceptait que `AllowTcpForwarding no` comme sûr :

```python
atf = cfg.get("allowtcpforwarding", "yes").lower()
if atf not in ("no",):
    result.warn(message=_t("ssh.allow_tcp_forwarding"), ...)
    result.add_deduction(reason=..., points=1, ...)
```

OpenSSH supporte une troisième valeur — `local` — qui ne permet le port forwarding qu'entre processus du serveur SSH lui-même, pas entre le client et des hôtes arbitraires. Plus restrictif que `yes`, il est explicitement recommandé dans le texte de remédiation BOB (champ `how` dans `locales/fr.json`) :

> « Si certains utilisateurs ont besoin du transfert de port, utilisez : `AllowTcpForwarding local` »

Définir `local` était donc à la fois *plus sécurisé que la valeur par défaut* et *contredit par le scoring BOB lui-même* : ça déclenchait l'avertissement et déduisait 1 point.

#### Implémentation

```python
if atf not in ("no", "local"):
```

`no` et `local` sont désormais tous deux acceptés. `yes` (défaut) et `all` continuent de déclencher l'avertissement.

---

### Correctif — En-tête journalisation UFW affiché quand UFW inactif

**Fichiers :** `bob/runner.py:233`

#### Problème

```python
# ---- CHECK 40 — UFW logging level ----
if not config.quiet:
    print_section(t("sections.ufw_logging"))
report.write_section(t("sections.ufw_logging"))

ufw_logging_result = check_ufw_logging(fw_status, t=t)
engine.apply(ufw_logging_result)
display_result(ufw_logging_result, report, ...)
```

`check_ufw_logging()` retourne un `CheckResult` vide quand UFW est inactif (lignes 407–408 de `firewall.py`), car le cas est déjà couvert par `check_firewall`. Mais l'en-tête de section est imprimé inconditionnellement, produisant ceci à l'écran et dans le rapport quand UFW est désactivé :

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  JOURNALISATION UFW                                                          │
└──────────────────────────────────────────────────────────────────────────────┘

```

…suivi immédiatement de la section suivante. Bruit visuel.

#### Implémentation

Tout le bloc encapsulé dans `if fw_status.active:`. Quand UFW est inactif, l'en-tête n'est pas imprimé et le résultat (vide) n'est pas affiché.

---

### Correctif — ULA et link-local IPv6 traités comme externes

**Fichiers :** `bob/checks/network_context.py:297`

#### Problème

`_is_private_or_loopback()` reconnaissait :
- Loopback IPv4 (`127.0.0.0/8`)
- RFC-1918 IPv4 (`10/8`, `172.16/12`, `192.168/16`)
- Loopback IPv6 (`::1`)

Mais omettait deux plages IPv6 importantes :
- `fc00::/7` — Unique Local Addresses (RFC-4193, équivalent IPv6 de RFC-1918)
- `fe80::/10` — adresses link-local (utilisées typiquement pour la découverte de voisins, pas pour la connectivité externe)

Une connexion entre deux adresses `fe80::` sur le même lien, ou deux `fc00::` sur un réseau privé, était classée comme *externe* — entraînant des avertissements faux positifs et une mauvaise catégorisation de l'exposition.

Le même module utilisait précédemment une vérification par préfixe de chaîne maison. À l'inverse, `bob/checks/auth_log.py` utilisait déjà `ipaddress.ip_network()` avec la liste correcte :

```python
_PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)
```

#### Implémentation

`network_context.py` utilise désormais le même tuple `_PRIVATE_NETWORKS` et la même vérification basée sur `ipaddress.ip_address()` :

```python
def _is_private_or_loopback(addr: str) -> bool:
    bare = addr.split("%", 1)[0]   # strip IPv6 zone-id (ex : "fe80::1%eth0")
    try:
        ip = ipaddress.ip_address(bare)
    except ValueError:
        return False
    return any(ip in net for net in _PRIVATE_NETWORKS)
```

Aligné avec `auth_log.py`. Le strip du `%` gère les zone identifiers dans les adresses link-local, que `ipaddress.ip_address()` n'accepte pas directement.

---

### Correctif — Regex `NOTIFY_EMAIL` legacy silencieusement ignoré

**Fichiers :** `bob/cron.py:820`, `bob/locales/en.json`, `bob/locales/fr.json`

#### Problème

`edit_cron_email()` patche la ligne `NOTIFY_EMAILS=` dans les scripts cron installés par BOB :

```python
text = re.sub(
    r"^NOTIFY_EMAILS=.*$",
    lambda _: f"NOTIFY_EMAILS={shlex.quote(new_email)}",
    text, flags=re.MULTILINE,
)
```

Les scripts pré-v0.x utilisaient le singulier `NOTIFY_EMAIL=` (sans S). Les utilisateurs ayant installé des crons avec une version précoce voyaient la fonction signaler le succès — mais aucune ligne ne matchait, donc rien ne changeait. Échec silencieux.

#### Implémentation

```python
text, n = re.subn(
    r"^NOTIFY_EMAILS?=.*$",   # match les deux formes
    lambda _: f"NOTIFY_EMAILS={shlex.quote(new_email)}",   # toujours réécrire au format actuel
    text, flags=re.MULTILINE,
)
if n == 0:
    print(f"  ⚠ {t('manage_cron.email_not_found_in_script')}")
```

`subn()` retourne le nombre de substitutions. Quand zéro, un avertissement est imprimé via une nouvelle clé locale :
- EN : `"No NOTIFY_EMAIL line found in the script — email not patched (script may be outdated)."`
- FR : `"Aucune ligne NOTIFY_EMAIL trouvée dans le script — email non mis à jour (script obsolète ?)."`

Les anciens scripts sont migrés vers la nouvelle clé (`NOTIFY_EMAILS=`) à la prochaine édition.

---

### Refactoring — `_check_weak_algo` déplacé dans la section sub-check

**Fichiers :** `bob/checks/ssh.py`

#### Problème

`bob/checks/ssh.py` est organisé par en-têtes de section :
- `# Sub-check functions` — `_check_host_keys`, `_check_sshd_config`, …
- `# Parsing helpers` — `_parse_config_file`, `_collect_private_keys`, …

`_check_weak_algo` (introduit en v0.3.5 pour dédupliquer la logique weak-cipher / weak-MAC / weak-kex) était placé sous `# Parsing helpers`. Mais il accepte un `CheckResult` et écrit des findings via `result.warn()` / `result.add_deduction()` — par tout signal pertinent c'est un sub-check, pas un helper de parsing.

#### Implémentation

Déplacé immédiatement après `_check_sshd_config` (son seul appelant), avant `_check_ssh_dir`. La section `# Parsing helpers` ne contient désormais que de vraies fonctions de parsing.

---

### Nettoyage — 22 imports inutilisés supprimés

**Fichiers :** `bob/__main__.py`, `bob/cron_ui.py`, `bob/output.py`, `bob/explain.py`, `bob/exposure.py`, `bob/registry.py`, `bob/report.py`, `bob/cron.py`, `bob/watch.py`, `bob/checks/iptables_nftables.py`, `bob/checks/firmware.py`, `bob/checks/ports.py`, `bob/checks/log_rotation.py`, `bob/checks/auth_log.py`, `bob/checks/logs.py`, `bob/checks/virtualization.py`, `bob/checks/smtp.py`, `bob/checks/disk.py`, `bob/checks/auditd.py`, `bob/checks/ddns.py`, `bob/checks/hardening.py`

#### Problème

`pyflakes bob/` reportait 22 imports inutilisés — vestiges de refactorings successifs (v0.3.0 → v0.3.5) :
- `dataclasses.field` dans 6 modules sans appel `field()` restant
- `typing.{Optional, List, Tuple, Dict}` dans 4 modules
- `pathlib.Path` dans 2 modules
- `bob.scoring.{ScoreEngine, Finding, FindingLevel}` dans `report.py` (bloc TYPE_CHECKING)
- `shutil` dans `output.py` et `cron.py` (re-import local)
- `bob.checks._run._C_LOCALE_ENV` dans `iptables_nftables.py`
- `bob.cron.prompt_emails`, `pathlib.Path` dans `cron_ui.py`
- `bob.config.UserConfig` dans `watch.py`
- `bob.webhook.WebhookError` dans `__main__.py` (remplacé par catch `Exception`)
- `bob.runner._ALL_SECTIONS` re-importé localement dans `__main__.py:91`

Plus trois problèmes structurels :
1. `bob/checks/logs.py:633` — paramètre `field` shadowait `dataclasses.field` de la ligne 25, déclenchant à la fois l'avertissement d'import inutilisé et un avertissement de redéfinition. Renommé en `field_name`.
2. `bob/checks/hardening.py:114` — variable locale `found_issue = False` assignée à 8 endroits (`found_issue = True`) mais jamais lue. Les 8 affectations et l'initialiseur supprimés.
3. `bob/output.py:351` — `bar = "─" * inner` calculé mais inutilisé ; `bob/cron_ui.py:244` — `_SCHEDULE_DAILY` dépaqueté d'un tuple mais jamais référencé (remplacé par `_`).

#### Implémentation

Chaque import a été tracé (grep du symbole dans le fichier) avant suppression. Là où un bloc TYPE_CHECKING devenait vide (`bob/report.py`), tout le bloc, y compris `if TYPE_CHECKING:`, a été supprimé.

L'unique avertissement pyflakes restant est `bob/__main__.py:24` — un re-export `# noqa: F401` intentionnel d'`AuditConfig` pour les appelants qui font `from bob.__main__ import AuditConfig`.

---

### Nettoyage — 47 clés de locales mortes supprimées

**Fichiers :** `bob/locales/en.json`, `bob/locales/fr.json`

#### Problème

Les deux fichiers de locales avaient grossi à 2049 lignes / 1435 clés chacun. Un audit de chaque clé contre les sites d'appel `t()` et `_t()` réels — incluant les patterns dynamiques comme `t(f"services.exposure.{name}")` et les références indirectes via les paramètres `t_key` dans les helpers — a révélé 47 clés vraiment orphelines.

#### Implémentation

Supprimées (groupées par parent) :

| Parent | Clés supprimées | Raison |
|--------|-----|--------|
| `cli.help_*` | 14 | Ancien système d'aide remplacé par `print_help()` codé en dur dans `cli.py:555` |
| `errors.*` | 3 | Objet entier : `must_be_root`, `unknown_option`, `ufw_not_found` (tous remplacés par exceptions) |
| `geo.*` | 1 | Objet entier : `local_network` |
| `profile.*` | 3 | Objet entier : `active`, `not_found`, `section_skipped` |
| `report.*` | 3 | `title`, `next_steps`, `system_info` |
| `cli.help`, `errors`, `geo`, `profile` | (objets) | Objets entiers vides supprimés |
| Diverses feuilles | 20 | `prerequisites.{ss_available, ss_missing}`, `network_context.{interfaces_found, no_connections, connections_found}`, `ports.ephemeral_ignored`, `logs.{geo_unavailable, local_network}`, `ddns.{ports_title, high_warn}`, `summary.block_normal`, `fixes.done`, `risk_context.level`, `log_dir.{default_hint, use}`, `install_cron.{prompt_email, done}`, `manage_cron.edit_schedule`, `config.{port_prompt, port_saved}`, `deduction.local_dominance`, `status.{ok, info}` |

Préservées malgré l'absence d'usage :
- `_meta.lang`, `_meta.version` — clés de métadonnées réservées

Les deux fichiers restent synchrones (1388 clés chacun, parité EN/FR vérifiée).

#### Notes de design

Audit effectué en extrayant chaque clé aplatie, puis en cherchant avec grep les usages statiques (`t("key.subkey")`) et dynamiques (`f"key.{var}"`). Approche conservatrice : toute clé avec ne serait-ce qu'une possibilité distante de référence dynamique a été conservée.

Lignes économisées : 2049 → 1994 (−55 par fichier, −110 au total).

---

### Tests

4348/4348 — aucun changement de tests. Tous les correctifs sont couverts par les tests existants ; aucune régression introduite. Pyflakes est propre (un seul `# noqa: F401` intentionnel restant pour le re-export `AuditConfig`).

Validé bout en bout sur so6desktop (Linux Mint 22.3) — audit complet avec score 8/10 (Pare-feu & Services 10/10, SSH 7/10, Durcissement 6/10) et toutes les sections correctement rendues. La section journalisation UFW apparaît (UFW actif) ; la section cohérence IPv6 indique « link-local uniquement » ; les profils, plugins et baselines sont correctement chargés depuis `/home/so6/.config/bob/`.

---

## [v0.3.5] — 08-05-2026

Refactoring interne pur et correctif des locales — aucune nouvelle fonctionnalité, aucun changement de comportement, aucun nouveau test. Deux tâches indépendantes plus un correctif de contenu : les blocs de sections répétitifs dans `runner.py` remplacés par une closure `_sec` (−295 lignes), la logique de vérification d'algorithmes faibles triplicata dans `ssh.py` remplacée par un helper `_check_weak_algo` (−26 lignes), et quatre clés de traduction référençant encore l'ancien nom d'outil `UFW-AUDIT` corrigées en `BOB`. 4348/4348 tests.

---

### Refactoring — closure `_sec` dans `runner.py`

**Fichiers :** `bob/runner.py` (951 L → 656 L, −295 lignes)

#### Problème

`run_checks()` contenait 29 blocs quasi-identiques de 7 à 13 lignes, un par section d'audit :

```python
if _section_enabled("kernel_modules", config, profile):
    if not config.quiet:
        print_section(t("sections.kernel_modules"))
    report.write_section(t("sections.kernel_modules"))
    result = check_kernel_modules(km_snapshot, t=t, profile_name=_pname)
    if profile is not None:
        apply_profile(result, profile)
    engine.apply(result)
    display_result(result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
    if not config.quiet:
        print()
```

951 lignes au total. La répétition rendait impossible l'ajout d'un traitement transversal (par ex. un hook entre chaque section) sans modifier 29 sites.

#### Implémentation

**`_pname` pré-calculé une fois** après `_pr` :

```python
_pname = profile.name if profile is not None else "server"
```

Utilisé par les 7 sections qui acceptent `profile_name=` : `kernel_modules`, `mac_policy`, `updates`, `memory`, `backup`, `auditd`, `secure_boot`. `check_firmware` n'accepte pas `profile_name` — intentionnellement exclu.

**Closure `_sec`** définie immédiatement après :

```python
def _sec(section: str, snapshot, check_fn, **check_kwargs) -> None:
    if not _section_enabled(section, config, profile):
        return
    if not config.quiet:
        print_section(t(f"sections.{section}"))
    report.write_section(t(f"sections.{section}"))
    result = check_fn(snapshot, t=t, **check_kwargs)
    if profile is not None:
        apply_profile(result, profile)
    engine.apply(result)
    display_result(result, report, config.verbose, quiet=config.quiet, recurrence=_pr)
    if not config.quiet:
        print()
```

29 blocs standards remplacés par des appels en une ligne :

```python
_sec("kernel_modules", km_snapshot,  check_kernel_modules,  profile_name=_pname)
_sec("ssh",           ssh_snapshot,  check_ssh,             ssh_exposed=_ssh_exposed)
_sec("ipv6",          ipv6_snapshot, check_ipv6,            ufw_active=fw_status.active)
# …et 26 autres
```

Sections conservées en manuel (non converties) : firewall, rules, ufw_logging, groupes réseau/affichage, samba, docker_audit, desktop_apps, iptables_nft (toutes comportent une logique conditionnelle autour de `.installed`, `.detected`, ou `not fw_status.active` qui ne peut pas être abstraite dans la closure sans ajouter de complexité).

**`apply_profile` maintenant appliqué à `auth_log`** — omis par inadvertance auparavant. Sans effet en pratique (aucun profil ne définit d'overrides spécifiques à auth_log), mais désormais cohérent avec toutes les autres sections.

#### Décisions de conception

- **Closure plutôt qu'helper module** : `_sec` capture `config`, `profile`, `engine`, `report`, `t`, `_pr` depuis la portée englobante. Un helper module nécessiterait de passer les six en paramètre à chaque appel — plus verbeux, aucun avantage.
- **`check_fn(snapshot, t=t, **check_kwargs)` et non `check_fn(snapshot, **{"t": t, **check_kwargs})`** : `t` est toujours positionnel-mot-clé ; la forme keyword-splat est correcte et explicite.

---

### Refactoring — helper `_check_weak_algo` dans `ssh.py`

**Fichiers :** `bob/checks/ssh.py` (1406 L → 1380 L, −26 lignes)

#### Problème

`_check_sshd_config()` contenait trois blocs identiques de 16 lignes pour vérifier les algorithmes Ciphers, MACs et KexAlgorithms faibles :

```python
cipher_str = cfg.get("ciphers", "")
if cipher_str:
    configured = {c.strip().lower() for c in cipher_str.split(",")}
    weak = sorted(configured & _WEAK_CIPHERS)
    if weak:
        joined = ", ".join(weak)
        result.warn(
            message=_t("ssh.weak_ciphers", ciphers=joined),
            nature="improvement", cmd="", key="ssh.weak_ciphers",
        )
        result.add_deduction(
            reason=_t("ssh.weak_ciphers", ciphers=joined),
            points=2, context="local", key="ssh.weak_ciphers",
        )
        found_issue = True
```

Répété pour `macs` et `kexalgorithms` avec seulement les noms de variables, ensembles, clés de traduction et valeurs de points qui diffèrent.

#### Implémentation

Helper module `_check_weak_algo` extrait avant `_parse_config_file` :

```python
def _check_weak_algo(
    cfg: dict, result: "CheckResult", _t,
    cfg_key: str, weak_set: "frozenset[str]", t_key: str, param: str, points: int,
) -> bool:
    """Flag weak crypto algorithm entries; return True if any found."""
    algo_str = cfg.get(cfg_key, "")
    if not algo_str:
        return False
    configured = {a.strip().lower() for a in algo_str.split(",")}
    weak = sorted(configured & weak_set)
    if not weak:
        return False
    joined = ", ".join(weak)
    result.warn(
        message=_t(t_key, **{param: joined}),
        nature="improvement", cmd="", key=t_key,
    )
    result.add_deduction(
        reason=_t(t_key, **{param: joined}),
        points=points, context="local", key=t_key,
    )
    return True
```

Trois sites d'appel dans `_check_sshd_config` :

```python
found_issue |= _check_weak_algo(cfg, result, _t, "ciphers",       _WEAK_CIPHERS, "ssh.weak_ciphers", "ciphers", 2)
found_issue |= _check_weak_algo(cfg, result, _t, "macs",          _WEAK_MACS,    "ssh.weak_macs",    "macs",    1)
found_issue |= _check_weak_algo(cfg, result, _t, "kexalgorithms", _WEAK_KEX,     "ssh.weak_kex",     "kex",     1)
```

#### Décision de conception

**Module plutôt que closure** : contrairement à `_sec`, ce helper reçoit toutes ses entrées en paramètres et ne dépend pas d'une portée extérieure. Une fonction module la rend indépendamment testable et visible pour d'éventuels futurs appelants.

---

### Correctif — chaînes de locale `UFW-AUDIT` → `BOB`

**Fichiers :** `bob/locales/en.json`, `bob/locales/fr.json`

#### Problème

Quatre clés de traduction dans les deux fichiers de locale référençaient encore l'ancien nom d'outil `UFW-AUDIT` au lieu de `BOB` :

| Clé | Avant (FR) | Après (FR) |
|-----|------------|------------|
| `install_cron.title` | `INSTALLATION CRON UFW-AUDIT` | `INSTALLATION CRON BOB` |
| `manage_cron.title` | `GESTION DES CRONS UFW-AUDIT` | `GESTION DES CRONS BOB` |
| `manage_cron.no_crons` | `Aucun cron UFW-AUDIT installé.` | `Aucun cron BOB installé.` |
| `report.title` | `RAPPORT UFW-AUDIT` | `RAPPORT BOB` |

Ces chaînes apparaissaient dans les écrans de configuration et gestion des crons, ainsi que dans le titre de section du rapport. Les autres références `UFW` dans les fichiers de locale sont légitimes — elles désignent l'outil pare-feu UFW lui-même, pas l'ancien nom d'outil.

#### Implémentation

Remplacement de chaîne simple dans `en.json` et `fr.json`. Aucun changement de logique.

---

## [v0.3.4] — 08-05-2026

Version hotfix — aucune nouvelle fonctionnalité, aucun changement de comportement, aucun nouveau test. Corrige un `NameError` fatal introduit en v0.3.2 : `user_config` n'était pas passé à `run_checks()`. 4348/4348 tests.

---

### Fix — `user_config` non passé à `run_checks()`

**Fichiers :** `bob/runner.py`, `bob/__main__.py`

#### Problème

La v0.3.2 a ajouté la whitelist SUID utilisateur. `run_checks()` a été étendue avec un appel à `user_config.get_suid_whitelist()` dans le bloc de vérification SUID (CHECK 37), mais `user_config` n'a jamais été ajouté comme paramètre de `run_checks()`. Le site d'appel dans `__main__.py` ne le passait donc pas.

Résultat : chaque audit atteignant le CHECK 37 (audit SUID/SGID) plantait avec :

```
NameError: name 'user_config' is not defined
```

Régression fatale sur toutes les machines — l'audit atteint toujours le CHECK 37.

#### Implémentation

`runner.py` — paramètre ajouté et accès protégé :

```python
def run_checks(
    ...
    user_config: UserConfig | None = None,   # ajouté
) -> ChecksResult:
    ...
    suid_snapshot = SuidSnapshot.from_system(
        user_whitelist=user_config.get_suid_whitelist() if user_config is not None else []
    )
```

`__main__.py` — site d'appel mis à jour pour passer `user_config`.

#### Validation

Testé sur 5 VMs (Linux Mint 22.3, Debian 13, Ubuntu 26.04, Kali, so6desktop) — audit complet sans erreur sur toutes.

---

## [v0.3.3] — 07-05-2026

Refactoring interne pur — aucune nouvelle fonctionnalité, aucun changement de comportement. Quatre tâches de nettoyage issues d'une passe de code review : découpage de `cron.py`, retour pur de `compute_domain_scores()`, API publique de `domain_scores`, helpers curses dans `cron_ui.py`. 4348/4348 tests (+1).

---

### Refactoring — découpage de `cron.py`

**Fichiers :** `bob/cron.py`, `bob/cron_ui.py` (nouveau)

#### Problème

`bob/cron.py` avait atteint 2 181 lignes en mélangeant des préoccupations hétérogènes : types de données, parsers, logique cron, flux interactifs en texte brut, et un TUI curses complet. Le code curses importait `curses` au niveau module, ce qui déclenchait une `_curses.error` à l'import dans tout test sans TTY. Les flux d'installation et de gestion contenaient chacun un bloc de génération de script bash de 40 lignes — logique identique copié-collée.

#### Implémentation

**Découpage**

`bob/cron.py` conserve tous les types de données, parsers, logique domaine, et flux interactifs en texte brut. `bob/cron_ui.py` (nouveau, 955L) contient tout le code TUI curses. Les dispatchers `run_install_cron()` / `run_manage_cron()` utilisent un pattern d'import paresseux :

```python
if sys.stdout.isatty():
    try:
        import curses
        curses.wrapper(_run_install_cron_curses)
    except curses.error:
        _run_install_cron_plain(...)
else:
    _run_install_cron_plain(...)
```

Le `import curses as _c` à l'intérieur des fonctions de `cron_ui.py` est intentionnel : le déplacer au niveau module casserait les imports dans les tests sans terminal.

**`build_script_content(notify_email, log_dir) -> str`**

Fonction pure extraite des deux flux d'installation dans `cron.py`, éliminant une duplication de 40 lignes. Retourne la chaîne complète du script bash. Appelée depuis `_run_install_cron_plain()` et `_run_install_cron_curses()`.

---

### Refactoring — retour pur de `compute_domain_scores()`

**Fichiers :** `bob/scoring.py`, `bob/domain_scores.py`, `bob/breakdown.py`

#### Problème

`compute_domain_scores()` communiquait quelles déductions étaient cappées en posant `deduction.was_capped = True` comme effet de bord sur des objets `Deduction` live. Non-idempotent (corrigé en v0.3.2 par un reset en début de fonction), mais la cause racine restait : une fonction qui mutait ses entrées pour transmettre une information aux appelants. `breakdown.py` itérait `engine.breakdown` et vérifiait `was_capped` pour annoter le tableau de breakdown.

#### Implémentation

Champ `Deduction.was_capped: bool` supprimé du dataclass.

`compute_domain_scores()` retourne désormais `tuple[dict[str, dict], frozenset[int]]` — le second élément est l'ensemble des indices dans `engine.breakdown` réduits par un cap de domaine. La fonction calcule ce frozenset purement par comparaison `effective < raw` sans toucher aucun objet.

`ScoreEngine.set_domain_scores()` reçoit un paramètre `capped_indices: frozenset[int]`, stocké en `_capped_indices`. Nouvelle propriété `capped_indices` pour l'exposer. `breakdown.py` lit `engine.capped_indices` au lieu d'inspecter `was_capped` sur chaque déduction.

#### Décisions de conception

- **`frozenset[int]` et non `set[Deduction]`** : les indices sont stables dans un appel `compute_domain_scores()` ; le frozenset est immuable et sûr en cache. Des références à des objets `Deduction` créeraient une dépendance implicite sur l'identité des objets.
- **Retour du frozenset plutôt que stockage interne** : la fonction n'a plus d'effets de bord, ce qui la rend trivialement testable par assertion directe sur la valeur de retour.

---

### Refactoring — API publique de `domain_scores.py`

**Fichiers :** `bob/domain_scores.py`, `bob/breakdown.py`, `bob/explain.py`, `tests/test_domain_scores.py`

#### Problème

Trois noms au niveau module — `_LABELS`, `_TOOL_CAPS`, `_key_to_domain` — étaient effectivement publics : utilisés directement par `breakdown.py` et `explain.py`. Le tiret bas suggérait qu'ils étaient des détails internes privés, mais des appelants externes en dépendaient. Signal trompeur : tout appelant voyant `from bob.domain_scores import _LABELS` savait qu'il importait un nom privé.

#### Implémentation

Renommage simple : `_LABELS → LABELS`, `_TOOL_CAPS → TOOL_CAPS`, `_key_to_domain → key_to_domain`. Tous les appelants mis à jour (`breakdown.py`, `explain.py`, `tests/test_domain_scores.py`). Aucune logique modifiée.

---

### Refactoring — helpers curses dans `cron_ui.py`

**Fichiers :** `bob/cron_ui.py`

#### Problème

`cron_ui.py` présentait trois catégories de duplication structurelle :

1. **Génération de script** : script bash de 40 lignes dupliqué entre les flux d'installation texte brut et curses (traité ci-dessus par `build_script_content`).
2. **`addstr` sécurisé** : chaque écriture à l'écran était enveloppée dans `try: stdscr.addstr(...) except _c.error: pass` — 30+ blocs identiques de 3 lignes.
3. **Lecture de touche** : chaque boucle interactive contenait `try: ch = stdscr.get_wch() / except _c.error: continue` suivi d'une normalisation `isinstance(ch, int)` / `isinstance(ch, str)` — 9 duplications séparées.
4. **Indices magiques de planning** : `if choice == 2 / 3 / 4` disséminé dans `_curses_schedule_wizard` sans explication de ce que signifient 2, 3, 4.
5. **Stub `_FakeEntry`** : une bare `class _FakeEntry: pass` avec attribut `entry.name = raw_name` posé au runtime — non typé, non documenté.

#### Implémentation

**`_WizardEntry(name, hour=3, minute=0)` NamedTuple**

Remplace `_FakeEntry`. Créé à `STEP_SCHEDULE` avec `_WizardEntry(raw_name)`, passé à `_curses_schedule_wizard`. Typé, documenté, immuable.

**`_draw(stdscr, row, col, text, attr=0) -> None`**

```python
def _draw(stdscr, row: int, col: int, text: str, attr: int = 0) -> None:
    try:
        stdscr.addstr(row, col, text, attr)
    except Exception:
        pass
```

Absorbe les 30+ blocs `try/except curses.error`. Utilise `except Exception` (et non `except _c.error`) car `curses` n'est pas importé au niveau module — `_c` est un alias local à l'intérieur de chaque fonction.

**`_read_key(stdscr) -> int`**

```python
def _read_key(stdscr) -> int:
    try:
        ch = stdscr.get_wch()
    except Exception:
        return -1
    if isinstance(ch, int):
        return ch
    if isinstance(ch, str) and len(ch) == 1:
        return ord(ch)
    return -1
```

Retourne -1 en cas d'erreur ou d'entrée non reconnue. Les appelants qui faisaient précédemment `continue` sur erreur laissent désormais tomber toutes les branches `if/elif` sans match — comportement de redémarrage de boucle identique. Le seul cas limite où `-1` pourrait être matché par erreur (`_run_manage_cron_curses` confirm-delete) a été audité : le guard `if key in (ord("y"), ord("Y"))` signifie que `-1` annule simplement, ce qui est le comportement "toute touche : annuler" documenté.

**`_SCHEDULE_DAILY/WEEKDAYS/MONTHDAYS/CUSTOM = 1, 2, 3, 4`**

Constantes nommées remplaçant les indices magiques dans `_curses_schedule_wizard`.

#### Résultat net

1 104L → 955L (−149 lignes, −13 %).

---

### Tests

4 348 / 4 348 (+1 par rapport à v0.3.2).

`TestWasCapped` (vérifiait le flag `was_capped`) remplacé par `TestCappedIndices` (7 tests) couvrant le contrat de retour frozenset de `compute_domain_scores()` : ensemble vide quand aucun cap n'est déclenché, indices corrects quand les caps s'appliquent, immuabilité du frozenset retourné.

---

## [v0.3.2] — 06-05-2026

Liste blanche SUID configurable par l'utilisateur : les patterns déclarés dans `~/.config/bob/config.conf` suppriment les binaires légitimes du warning "SUID inattendu". Plus 14 corrections issues d'une passe de code review (i18n, mode quiet, idempotence moteur, code mort). 4347/4347 tests (+19).

---

### Fonctionnalité — `suid_whitelist` dans `config.conf`

**Fichiers :** `bob/config.py`, `bob/checks/suid_audit.py`, `bob/runner.py`, locales

#### Problème

Sur Kali Linux et autres distributions orientées sécurité, des outils légitimes sont livrés avec le bit SUID positionné (Kismet livre 15+ helpers de capture `kismet_cap_*`, tous root-owned SUID). Ces binaires apparaissent comme "inattendus" dans le rapport BOB — générant 15 avertissements parasites par exécution. Une liste blanche globale codée en dur serait incorrecte : ces binaires n'ont rien à faire sur un serveur de production. La configuration par utilisateur est la seule solution propre.

#### Implémentation

**`bob/config.py` — `UserConfig.get_suid_whitelist() -> list[str]`**

Nouveau helper qui lit la clé `suid_whitelist` dans `~/.config/bob/config.conf`, divise sur les virgules et retourne une liste de patterns glob nettoyés. Retourne `[]` quand la clé est absente ou vide. Suit le pattern existant des helpers `get_profile()` / `get_webhook_url()`.

```
# ~/.config/bob/config.conf
suid_whitelist = kismet_cap_*, mon_outil_maison
```

**`bob/checks/suid_audit.py` — `SuidSnapshot`**

- `SuidSnapshot` reçoit un nouveau champ `whitelisted_suid: list[str]` (défaut `[]`), stockant les chemins supprimés par les patterns utilisateur.
- `SuidSnapshot.from_system()` reçoit un paramètre `user_whitelist: list[str] | None = None`.
- Après le filtre sur `_KNOWN_SUID`, un second passage applique `fnmatch.fnmatch(basename, pattern)` pour chaque pattern utilisateur. Les chemins correspondants passent de `unexpected_suid` à `whitelisted_suid`.
- `check_suid_audit()` émet `suid_audit.whitelisted` (INFO) quand `snapshot.whitelisted_suid` est non vide, avec le nombre et les chemins. Intentionnellement visible — l'utilisateur doit voir que la suppression a eu lieu.

**`bob/runner.py`**

`SuidSnapshot.from_system(user_whitelist=user_config.get_suid_whitelist())` — la liste blanche est chargée depuis `user_config` (déjà dans scope) et passée à l'appel.

#### Décisions de conception

- **Glob sur le basename uniquement** : un matching sur le chemin complet permettrait à des patterns comme `*/opt/*` de supprimer tout ce qui est sous `/opt`. Le matching sur basename est prévisible et sûr.
- **INFO, pas invisible** : les chemins whitelistés sont rapportés en INFO plutôt que silencieusement supprimés. Si l'utilisateur whiteliste accidentellement `*`, il verra tous ses binaires SUID listés comme "supprimés par la liste blanche" et comprendra qu'il y a un problème.
- **Patterns séparés par virgules** : cohérent avec la façon dont la liste blanche `_KNOWN_SUID` fonctionne conceptuellement, et facilement éditable dans un fichier texte brut.

---

### Corrections — passe de code review (14 éléments)

Une revue systématique de la base de code a identifié et corrigé les problèmes suivants :

**BUG-2 — `compute_domain_scores()` non-idempotent (`domain_scores.py`)**
La fonction mutait `deduction.was_capped = True` sur des objets `Deduction` live. Un deuxième appel flipperait des flags supplémentaires sans raison. Correction : reset de tous les `was_capped = False` en début de `compute_domain_scores()` avant tout calcul.

**BUG-3 — `samba` et `desktop_apps` invisibles à `--check`/`--skip` (`runner.py`)**
Les deux sections étaient protégées par `_section_enabled()` mais absentes de `_ALL_SECTIONS`. `--list-checks` ne les montrait jamais ; `--check samba` était un no-op silencieux. Correction : les deux noms ajoutés à `_ALL_SECTIONS`.

**BUG-4 — Mode quiet contourné par toutes les lignes de statut (`output.py`)**
`_print_status()` et `print_risk_context()` utilisaient `print()` brut au lieu du wrapper `_p()` qui vérifie `_quiet`. Tous les `print_warn` / `print_alert` / `print_ok` / `print_info` atteignaient stdout même en mode `--quiet`. Correction : tous les `print()` remplacés par `_p()` dans ces deux fonctions.

**BUG-1 — Labels français codés en dur dans `output.py`**
`print_warn()` émettait `[ATTENTION]` et `print_alert()` émettait `[ALERTE]` inconditionnellement, même sur une install anglaise. Les clés i18n `status.warn = "WARNING"` et `status.alert = "ALERT"` existaient dans `locales/en.json` mais n'étaient jamais appelées. Correction : les deux fonctions appellent désormais `t("status.warn")` / `t("status.alert")` via un import local de `bob.i18n`.

**BUG-5 — Attribut dynamique `result._log_data` sur un dataclass (`scoring.py`, `checks/logs.py`, `display.py`)**
`check_logs()` posait un attribut `result._log_data` non déclaré avec `# type: ignore`. En cas de chemin d'early-return, `display_log_results()` n'affichait rien silencieusement. Correction : `CheckResult` reçoit un champ propre `log_data: dict | None = field(default=None)` ; `logs.py` et `display.py` mis à jour.

**BUG-6 — Déductions bruteforce sans `key=` (`checks/logs.py`)**
`result.warn()` et `result.add_deduction()` dans la boucle bruteforce n'avaient pas de `key=`, les rendant invisibles à `--ignore` et aux profils. Correction : `key="logs.brute_found"` ajouté aux deux appels.

**SF-1 — Parse de `sshd_config` silencieusement tronquée aux blocs `Match` (`checks/ssh.py`)**
Quand un bloc `Match` apparaissait dans `sshd_config`, les directives globales suivantes étaient silencieusement ignorées. Le check pouvait rapporter un faux OK. Correction : `_parse_config_file()` pose `config["_match_block"] = True` ; `_check_sshd_config()` émet `ssh.match_block_skipped` (INFO).

**SF-2 — `curr_baseline` potentiellement non lié (`__main__.py`)**
`curr_baseline` était assigné à l'intérieur d'un bloc `with redirect_stdout(...)`. Un futur refactoring qui briserait le couplage `diff_mode` provoquerait une `UnboundLocalError`. Correction : `curr_baseline = None` initialisé avant le bloc.

**SEC-1 — `fixes.py` ignore `--no-color` (`fixes.py`)**
Tous les literals `\033[...]` dans `fixes.py` contournaient le flag `--no-color` et l'infrastructure `output._c`. Rediriger la sortie des fixes vers un fichier produisait des séquences d'échappement brutes. Correction : tous les literals remplacés par `output._c.*`.

**BP-2 — Module externe écrivait sur des attributs `_privés` du moteur (`scoring.py`, `domain_scores.py`)**
`apply_domain_score_override()` posait directement `engine._domain_scores` et `engine._active_domains`, couplant `domain_scores.py` aux internals de `ScoreEngine`. Correction : méthode publique `ScoreEngine.set_domain_scores(scores, active)` ajoutée.

**BP-3 — Comparaison de chaîne sur la valeur d'un enum (`checks/ssh.py`)**
`f.level.value in ("warn", "alert", "info")` se briserait silencieusement si un membre de `FindingLevel` était renommé. Correction : `f.level != FindingLevel.OK`.

**BP-1 — `open(os.devnull)` sans `encoding=` (`__main__.py`)**
Ouverture de fichier en mode texte sans encodage explicite. Correction : `encoding="utf-8"` ajouté.

**INC-2 — `snapshot.from_system()` s'exécutait avant le guard `_section_enabled()` (`runner.py`)**
`SambaSnapshot.from_system()` et `DesktopAppsSnapshot.from_system()` (qui exécutent des requêtes `dpkg`/subprocess) étaient appelés inconditionnellement, même lors d'un `--skip`. Correction : appels `from_system()` déplacés à l'intérieur du guard `_section_enabled()`.

**DC-1 — `_is_root_owned()` code mort (`checks/suid_audit.py`)**
Helper privé jamais appelé en production ; la logique inline à la ligne 165 faisait déjà la même chose. Correction : fonction supprimée, ses deux tests unitaires supprimés.

---

## [v0.3.1] — 06-05-2026

Deux corrections de bugs identifiées lors de la validation multi-VM, plus deux refactorisations architecturales dans le pipeline de décomposition du score. Aucune nouvelle fonctionnalité. 4328/4328 tests (+6).

---

### Correction 1 — Version bannière bloquée à `0.2.4` (`bob/__init__.py`)

#### Problème

Après la sortie de v0.3.0, `bob/__init__.py` déclarait encore `__version__ = "0.2.4"`. La bannière ASCII affichée par `print_banner()` et la sortie de `bob -V` / `bob --version` lisent toutes deux la version depuis cet attribut de module, donc toutes les plateformes affichaient `BOB v0.2.4` au lieu de `BOB v0.3.0`. Découvert immédiatement lors du premier audit VM post-v0.3.0.

#### Correction

`__version__ = "0.2.4"` → `"0.3.1"`. Aucun autre changement de code — la chaîne de version est l'unique source de vérité pour la bannière, le flag de version, et le champ `meta.version` de la sortie JSON.

---

### Correction 2 — Contexte réseau DDNS non propagé vers l'entête du score (`bob/runner.py`, `bob/__main__.py`)

#### Problème

`run_checks()` appelle `ddns_effective_context()` en interne pour upgrader `network_context` de `"local"` à `"ddns"` quand un client DDNS actif est détecté avec des ports ouverts. La fonction retournait correctement, mais `ChecksResult` — le NamedTuple retourné par `run_checks()` — ne contenait pas de champ `network_context`. `__main__.py` utilisait donc toujours sa valeur initiale (`"local"`) pour l'entête du résumé et l'affichage d'exposition, quels que soient les résultats du check DDNS.

L'effet : les machines faisant tourner ddclient/inadyn/No-IP/DuckDNS avec des ports ouverts affichaient "Réseau local uniquement" dans l'entête du score au lieu de "Exposition publique via DDNS". Le calcul du score lui-même était correct (la pénalité d'exposition est appliquée dans `run_checks()` avant que la valeur du contexte importe pour l'affichage), seule l'étiquette de l'entête était erronée.

Découvert lors de la validation de la VM Kali avec un client DDNS actif.

#### Correction

`network_context: str = "local"` ajouté comme dernier champ de `ChecksResult`. L'instruction `return ChecksResult(...)` dans `run_checks()` inclut désormais `network_context=network_context`. Dans `__main__.py`, `network_context = result.network_context` est assigné immédiatement après `result = run_checks(...)`, remplaçant la variable locale obsolète.

---

### Refactorisation 1 — `was_capped: bool` sur `Deduction` (`bob/scoring.py`, `bob/domain_scores.py`, `bob/breakdown.py`)

#### Problème

`bob/breakdown.py` déclare dans son docstring de module : *"Nothing is computed here — all data comes from the already-finalized engine."* Pourtant, la section de résumé des plafonds outil ré-implémentait le calcul des plafonds depuis zéro, maintenant un dict `tool_contributed` local et itérant deux fois sur le breakdown pour identifier les entrées plafonnées. Cela dupliquait la logique de `compute_domain_scores()` et constituait une source latente de divergence.

#### Correction

`Deduction` (dans `bob/scoring.py`) gagne `was_capped: bool = False`. `compute_domain_scores()` (dans `bob/domain_scores.py`) positionne `deduction.was_capped = True` à deux endroits :

- Quand `allowed <= 0` (totalement absorbé — la déduction ne contribue rien à son domaine).
- Quand `allowed < points` (partiellement absorbé — seule une partie de la déduction est comptée).

`breakdown.py` lit `d.was_capped` directement dans la boucle du tableau de déductions (pour l'annotation `[plafonné]`) et utilise une compréhension d'ensemble sur `d.was_capped` pour construire l'ensemble `capped_prefixes` pour le résumé des plafonds outil. Le suivi local `tool_contributed` et `capped_entries` est supprimé entièrement.

---

### Refactorisation 2 — Propriétés `engine.domain_scores` / `engine.active_domains` en cache (`bob/scoring.py`, `bob/domain_scores.py`, `bob/__main__.py`, `bob/breakdown.py`)

#### Problème

Après `apply_domain_score_override()`, les scores par domaine et l'ensemble de domaines actifs sont stables — ils ne changeront plus. Pourtant `__main__.py` et `breakdown.py` importaient et appelaient `compute_domain_scores()` et `active_domains_from_engine()` séparément, ce qui entraînait un double calcul par audit. Toute divergence future entre les deux sites d'appel produirait un affichage incohérent.

#### Correction

`ScoreEngine.__init__()` initialise deux caches privés : `_domain_scores: dict | None = None` et `_active_domains: frozenset | None = None`. `apply_domain_score_override()` leur assigne les résultats après calcul :

```python
engine._domain_scores  = scores
engine._active_domains = active
```

Deux méthodes `@property` les exposent :

```python
@property
def domain_scores(self) -> dict:
    return self._domain_scores or {}

@property
def active_domains(self) -> frozenset:
    return self._active_domains or frozenset()
```

`__main__.py` et `breakdown.py` basculent tous deux vers `engine.domain_scores` et `engine.active_domains`. Les imports directs de `compute_domain_scores` et `active_domains_from_engine` sont supprimés de `__main__.py`.

---

### Tests

4328/4328 (+6 nouveaux) :

| Fichier | Classe | Test | Couverture |
|---------|--------|------|------------|
| `tests/test_domain_scores.py` | `TestWasCapped` | `test_uncapped_deduction_not_marked` | Déduction dans le plafond → `was_capped` reste `False` |
| `tests/test_domain_scores.py` | `TestWasCapped` | `test_fully_absorbed_deduction_marked` | Déduction après épuisement du plafond → `was_capped = True` |
| `tests/test_domain_scores.py` | `TestWasCapped` | `test_partially_absorbed_deduction_marked` | Déduction dépasse le plafond restant → `was_capped = True` |
| `tests/test_domain_scores.py` | `TestWasCapped` | `test_non_tool_cap_key_never_marked` | Clé sans préfixe de plafond outil → `was_capped` toujours `False` |
| `tests/test_domain_scores.py` | `TestWasCapped` | `test_cached_domain_scores_on_engine` | Après surcharge, `engine.domain_scores` correspond à `compute_domain_scores()` |
| `tests/test_domain_scores.py` | `TestWasCapped` | `test_engine_domain_scores_empty_before_override` | Avant surcharge, `engine.domain_scores` retourne `{}` |

---

## [v0.3.0] — 06-05-2026

Jalon transparence du scoring. Nouvelle option `--breakdown` (`-B`) affichant le chemin complet de calcul du score après un audit. `--explain <clé>` gagne une section SCORING. Trois corrections ciblées : asymétrie `-unsigned` dans la logique de rétention des kernels, flèche `→` orpheline sur les deltas de score stables, et reliques "UFW-AU" dans le rapport détaillé. 4322/4322 tests (+48).

---

### Fonctionnalité 1 — option `--breakdown` / `-B` (`bob/breakdown.py`, `bob/cli.py`, `bob/__main__.py`, `bob/locales/en.json`, `bob/locales/fr.json`)

#### Motivation

Le scoring de BOB utilise un pipeline multicouche : déductions par vérification → plafonds par outil → plafond moteur → surcharge de moyenne par domaine. Le score final était visible mais pas sa dérivation. Les utilisateurs voyant un 6/10 n'avaient aucun moyen de comprendre quelles déductions avaient contribué, si un plafond avait été déclenché, ou comment la moyenne par domaine avait modifié le résultat.

#### Implémentation

Nouveau module `bob/breakdown.py` — `display_breakdown(engine, t, output_mod)` — lit le `ScoreEngine` déjà finalisé et affiche :

1. **Déductions** — tableau complet (clé · domaine · points · contexte), avec annotation `[plafonné]` pour les entrées absorbées par un plafond outil.
2. **Plafonds par outil** — une ligne `[INFO]` par outil où les déductions brutes totales dépassent le plafond.
3. **Plafond moteur** — ligne `[ATTENTION]` si `engine.cap_info` est défini (ex. "pare-feu inactif — plafond à 3").
4. **Score brut** — `engine._raw_score` avant la moyenne par domaine.
5. **Scores par domaine** — chaque domaine actif avec score, déductions, et barre de progression sur 10 caractères.
6. **Surcharge de moyenne** — ligne `[INFO]` montrant la moyenne calculée et le nombre de domaines actifs, quand `engine._global_override is not None`.
7. **Score final** — coloré : vert (≥ 8), jaune (≥ 5), rouge (< 5).

Les labels de domaine sont traduits via `_domain_label(domain_id, t)` — essaie d'abord `t(f"domain_scores.{domain_id}")` (même pattern que `render_domain_scores`), se rabat sur `_LABELS` puis `domain_id.capitalize()`. Cela assure l'apparition des labels français (ex. "Durcissement") lors de l'exécution avec `--french`.

**Gestion de stdout** — `breakdown_mode` est ajouté à `_silent_mode` dans `__main__.py`. Tout l'audit s'exécute dans `with redirect_stdout(devnull)`, supprimant tous les appels `print()` nus (pas seulement les appels `output.*`, déjà supprimés par `quiet=True`). Après le bloc `with`, stdout est restauré et `display_breakdown` est appelé avec `output` réinitialisé sans `quiet`. C'est le même pattern qu'utilise `diff_mode` et les formats lisibles par machine.

#### i18n

Nouvelle section `breakdown.*` dans les deux fichiers de locales :

| Clé | Rôle |
|-----|------|
| `breakdown.section_title` | En-tête de section |
| `breakdown.no_deductions` | Message OK quand aucune déduction |
| `breakdown.deductions_header` | Sous-en-tête "N déduction(s) :" |
| `breakdown.capped` | Annotation pour les entrées plafonnées |
| `breakdown.tool_cap_applied` | Ligne info plafond outil |
| `breakdown.engine_cap_applied` | Ligne attention plafond moteur |
| `breakdown.raw_score` | Ligne score brut |
| `breakdown.domain_scores_header` | Sous-en-tête scores par domaine |
| `breakdown.domain_average` | Ligne surcharge moyenne domaine |
| `breakdown.final_score` | Ligne score final |

#### CLI

`-B` / `--breakdown` ajouté à `bob/cli.py` comme option booléenne. `_silent_mode` dans `__main__.py` étendu : `_machine_mode or config.breakdown_mode or config.diff_mode`.

---

### Fonctionnalité 2 — `--explain` score-aware (`bob/explain.py`)

#### Problème

`bob --explain <clé>` affichait les étapes de remédiation mais ne donnait aucune indication sur la contribution de la clé au score — son domaine d'appartenance, si un plafond outil limitait ses déductions, ou comment voir son impact en direct.

#### Correction

Nouvelle fonction `_explain_scoring(key, t)` ajoutée à la fin de chaque appel `run_explain()`. Lit `_key_to_domain(key)` et `_TOOL_CAPS.get(prefix)` depuis `bob/domain_scores.py` et affiche :

```
SCORING
────────────────────────────────────────
  Domain   : Durcissement
  Tool cap : max 2 pt total for 'hardening' deductions in this domain
  Impact   : run 'sudo bob --breakdown' to see this key's current score contribution
```

Les clés sans mapping de domaine (ex. clés info génériques) ignorent silencieusement la section.

---

### Correction 1 — Asymétrie de rétention kernel `-unsigned` (`bob/checks/kernel_modules.py`, `tests/test_kernel_modules.py`)

#### Problème

Sur les systèmes Debian, les paquets kernel signés et non-signés sont installés côte à côte :

```
linux-image-6.12.74+deb13+1-amd64
linux-image-6.12.74+deb13+1-amd64-unsigned
```

`_kernel_sort_key()` produit des tuples numériques identiques pour les deux (même `MAJOR.MINOR.PATCH+ABI`). Quand les tuples sont égaux, le tri de Python est stable, ce qui fait que la variante non-signée (apparaissant plus tard dans la sortie dpkg) se retrouve en dernière position dans la liste triée et devient `most_recent`.

La boucle de rétention remplit les slots du plus récent vers le plus ancien. Avec trois kernels installés et `keep_count=3` (profil server), la boucle remplit : `running`, `most_recent` (non-signé), et un kernel plus ancien. La variante signée de la même version que `most_recent` n'obtient pas de slot et atterrit dans `to_remove` — incorrectement marquée comme obsolète.

#### Correction

Après la boucle de rétention, étendre l'ensemble de conservation pour inclure les deux variantes de chaque version de base conservée :

```python
kernel_set = set(kernels)
for k in list(to_keep):
    base = _strip_unsigned(k)
    if base in kernel_set:
        to_keep.add(base)
    unsigned = f"{base}-unsigned"
    if unsigned in kernel_set:
        to_keep.add(unsigned)
```

`_strip_unsigned()` existait déjà dans le module. Cette expansion est O(keep_count) et s'exécute une seule fois après la boucle.

De plus, le message de détail des kernels obsolètes a été modifié de `recent=most_recent` à `recent=running`. Le conseil de vérification après redémarrage ("vérifiez que le système démarre correctement avant de supprimer les anciens kernels") doit référencer le kernel effectivement en cours d'exécution, pas le sibling `-unsigned` qui trie en dernier par hasard.

---

### Correction 2 — Flèche `→` orpheline dans le delta de score (`bob/display.py`)

#### Problème

Dans `print_audit_summary()`, la ligne de score est construite ainsi :

```python
score_str = f"{score}/10"
if prev_score is not None:
    delta = score - prev_score
    if delta > 0:
        score_str += f"  ↑ +{delta}"
    elif delta < 0:
        score_str += f"  ↓ {delta}"
    else:
        score_str += f"  →"
```

Quand le score était identique (`delta == 0`), la ligne affichait `6/10  →` sans rien après la flèche. La flèche était censée indiquer "stable" mais ressemblait à une ligne tronquée dans l'affichage de la boîte.

#### Correction

```python
    else:
        score_str += f"  = {score}"
```

"= 6" est sans ambiguïté : le score est égal à la valeur précédente.

---

### Correction 3 — Reliques "UFW-AU" dans le rapport détaillé (`bob/report.py`, `bob/report_markdown.py`)

#### Problème

`AuditReport.write_header()` contenait des tableaux de lettres ASCII codés en dur représentant "UFW-AU" — l'acronyme de l'ancien nom d'outil "ufw-audit". La liste de groupes de lettres était `[U, F, W, TIRET, A, U]`. L'en-tête imprimait aussi `UFW : ufw {version}` précédé de l'étiquette `UFW`.

Dans `report_markdown.py`, l'entrée pare-feu était étiquetée `**UFW:**`.

#### Correction

`bob/report.py` — groupes de lettres remplacés par `[B, O, B]` en utilisant la même police Doom block déjà utilisée dans le bandeau terminal de `output.py`. Étiquette d'en-tête changée en `Firewall : ufw {info.ufw_version}`.

`bob/report_markdown.py` — étiquette changée en `**Firewall (UFW):**`.

---

### Tests

4322/4322 (+48 nouveaux) :

#### `tests/test_breakdown.py` (nouveau fichier, +16)

| Classe | Test | Couverture |
|--------|------|------------|
| `TestBar` | `test_full_score_all_filled` | Score 10 → tous les blocs remplis |
| `TestBar` | `test_zero_score_all_empty` | Score 0 → tous les blocs vides |
| `TestBar` | `test_five_half_filled` | Score 5 → moitié remplie |
| `TestDisplayBreakdownClean` | `test_no_deductions_message` | Aucune déduction → clé `no_deductions` affichée |
| `TestDisplayBreakdownClean` | `test_section_title_printed` | En-tête de section affiché |
| `TestDisplayBreakdownClean` | `test_final_score_ten_shown` | Score 10 → clé `breakdown.final_score` affichée |
| `TestDisplayBreakdownWithDeductions` | `test_deductions_header_shown` | Déductions présentes → en-tête affiché |
| `TestDisplayBreakdownWithDeductions` | `test_deduction_keys_shown` | Chaque clé de déduction apparaît dans la sortie |
| `TestDisplayBreakdownWithDeductions` | `test_raw_score_shown` | Clé `breakdown.raw_score` affichée |
| `TestDisplayBreakdownWithDeductions` | `test_domain_scores_header_shown` | Domaines actifs → en-tête affiché |
| `TestDisplayBreakdownWithDeductions` | `test_domain_average_shown` | Surcharge globale définie → `breakdown.domain_average` affiché |
| `TestDisplayBreakdownWithDeductions` | `test_final_score_shown` | Clé `breakdown.final_score` affichée |
| `TestDisplayBreakdownToolCap` | `test_tool_cap_message_shown_when_exceeded` | Déductions totales > plafond → ligne info plafond outil affichée |
| `TestDisplayBreakdownToolCap` | `test_no_tool_cap_message_when_within_limit` | Déductions totales ≤ plafond → pas de message plafond outil |
| `TestDisplayBreakdownEngineCap` | `test_engine_cap_message_shown` | `engine.cap_info` défini → `breakdown.engine_cap_applied` affiché |
| `TestDisplayBreakdownEngineCap` | `test_engine_cap_message_not_shown_when_absent` | Pas de plafond → pas de message plafond |

#### `tests/test_golden_scenarios.py` (nouveau fichier, +32)

| Classe | Tests | Couverture |
|--------|-------|------------|
| `TestCleanMachine` | 4 | Score 10/10 ; pas de breakdown ; aucun domaine actif ; findings INFO exclus de l'activation des domaines |
| `TestHardenedServer` | 3 | 2 déductions durcissement → score 8 ; déductions par domaine ; assertions breakdown brut |
| `TestDefaultDesktop` | 3 | 4 déductions sur 3 domaines → score 9 ; déductions exactes par domaine |
| `TestPoorlyConfiguredServer` | 3 | Score brut 3 ; moyenne domaines 8 ; moyenne supérieure au score brut |
| `TestFirewallInactive` | 3 | Plafond moteur appliqué à 3 ; moyenne domaine peut dépasser le brut plafonné ; `cap_info` stocké |
| `TestDebian13Minimal` | 4 | Score brut 2 ; moyenne domaines 6 ; plafond outil rootkit ; 6 déductions durcissement après plafond |
| `TestToolCapInvariants` | 4 | rootkit/clamav/file_integrity plafonnés à 1pt chacun ; outil non-plafonné (ssh) s'accumule normalement |
| `TestScoreStability` | 5 | Indépendance d'ordre ; monotonicité même-domaine ; indépendance des domaines ; score ∈ [0, MAX_SCORE] ; plancher brut à 0 |
| `TestMultiDomainMachine` | 3 | 5 domaines actifs exact (frozenset) ; chaque domaine déduit une fois ; score 9 |

#### `tests/test_min_level.py` (mis à jour, 0 nouveau net)

`test_stable_shows_right_arrow` renommé en `test_stable_shows_equal` ; assertion mise à jour de `"→" in val` vers `"= 7" in val`. Docstring du module mis à jour en conséquence.

---

## [v0.2.4] — 05-05-2026

Passe de durcissement du codebase post-audit, déclenchée par une revue systématique de l'ensemble du projet à la suite de la tournée multi-VM v0.2.3. Deux bugs UX kernel Debian `-unsigned` corrigés, une régression dans le pattern sentinel `deduction_total` résolue, les annotations de type propagées à toutes les signatures de vérification, la détection des opérateurs shell durcie, et le fallback de profil rendu visible. Aucun nouveau check, aucun changement comportemental. 4274/4274 tests (+12).

---

### Fix 1 — `kernels_up_to_date` nomme le kernel courant, pas le sibling `-unsigned` (`bob/checks/kernel_modules.py`, `tests/test_kernel_modules.py`)

#### Problème

Sur les systèmes Debian avec les deux variantes d'un package kernel installées (ex. `linux-image-6.12.74+deb13+1-amd64` et `linux-image-6.12.74+deb13+1-amd64-unsigned`), `_kernel_sort_key()` les trie alphabétiquement après correspondance sur le même préfixe numérique. La variante non-signée se retrouve en dernière position et devient `most_recent`.

Dans `_check_installed_kernels()`, le message OK "kernel à jour" passait `version=most_recent` :

```python
result.ok(
    message=_t("kernel_modules.kernels_up_to_date", version=most_recent),
    ...
)
```

Quand `running = "6.12.74+deb13+1-amd64"` et `most_recent = "6.12.74+deb13+1-amd64-unsigned"`, le message affiché nommait le sibling `-unsigned` plutôt que le kernel dans lequel le système avait réellement démarré.

#### Correction

```python
result.ok(
    message=_t("kernel_modules.kernels_up_to_date", version=running),
    ...
)
```

Le message nomme maintenant toujours le kernel courant, quelle que soit la variante triée en dernier.

---

### Fix 2 — Bon template de message pour les paires signées/non-signées (`bob/checks/kernel_modules.py`, `tests/test_kernel_modules.py`)

#### Problème

`_check_installed_kernels()` sélectionne entre deux templates de message i18n :

- `kernels_obsolete_same` — utilisé quand `running == most_recent` (le kernel courant est le plus récent ; certains anciens peuvent être nettoyés). Pas de paire "courant / récent" dans le texte.
- `kernels_obsolete` — utilisé quand `running != most_recent` (un redémarrage mettrait à jour le kernel). Inclut les deux versions dans le texte.

La comparaison était littérale :

```python
if running == most_recent:
    _msg = _t("kernel_modules.kernels_obsolete_same", ...)
else:
    _msg = _t("kernel_modules.kernels_obsolete", ...)
```

Sur Debian avec une paire signé/non-signé, `running = "6.12.74+deb13+1-amd64"` et `most_recent = "6.12.74+deb13+1-amd64-unsigned"`. Ce sont sémantiquement la même version de kernel (même ABI, même niveau de sécurité), mais la comparaison littérale retourne `False`. L'outil utilisait incorrectement `kernels_obsolete`, sous-entendant que l'utilisateur devait redémarrer pour appliquer un kernel plus récent — factuellement faux.

`_strip_unsigned()` existait déjà dans le module précisément pour cette normalisation mais n'était pas appliqué dans ce chemin de code.

#### Correction

```python
if _strip_unsigned(running) == _strip_unsigned(most_recent):
    _msg = _t("kernel_modules.kernels_obsolete_same", ...)
else:
    _msg = _t("kernel_modules.kernels_obsolete", ...)
```

Les deux côtés sont normalisés avant la comparaison. Une paire signé/non-signé sélectionne maintenant correctement `kernels_obsolete_same`.

---

### Fix 3 — Sentinel `None` pour `deduction_total` évite un faux delta lors de la mise à jour (`bob/compare.py`, `tests/test_compare.py`)

#### Problème

v0.2.3 a introduit `deduction_total: int = 0` dans `AuditBaseline` et affichait un message "Déductions variables ±N pt(s)" dans `display_delta()` quand `deduction_delta != 0`. La valeur par défaut était `0`, et `load_baseline()` utilisait :

```python
deduction_total=int(raw.get("deduction_total", 0))
```

Les fichiers JSON de baseline pré-v0.2.3 ne contiennent pas la clé `"deduction_total"`. L'appel retournait `0`. Au premier audit suivant, `deduction_delta = curr.deduction_total - 0`. Comme `curr.deduction_total` est presque toujours positif (il y a presque toujours des déductions), le message des déductions variables apparaissait à chaque première exécution après une mise à jour depuis un baseline pré-v0.2.3 — un faux positif : rien n'avait réellement changé, le champ n'existait simplement pas dans l'ancien baseline.

C'est exactement le même mode d'échec que celui déjà résolu pour `finding_keys` avec le sentinel `list[str] | None = None`.

#### Correction

```python
# AuditBaseline
deduction_total: int | None = None   # None = baseline pré-v0.2.3 (champ absent)

# load_baseline()
deduction_total=int(raw["deduction_total"]) if isinstance(raw.get("deduction_total"), int) else None,

# compute_delta()
deduction_delta=(
    curr.deduction_total - prev.deduction_total
    if prev.deduction_total is not None and curr.deduction_total is not None
    else 0
),
```

`None` signifie "l'audit précédent est antérieur à l'introduction du champ". Le calcul du delta est ignoré pour ces baselines, produisant `deduction_delta = 0` et supprimant le message. Les nouveaux baselines écrivent toujours un entier ; les comparaisons suivantes se comportent normalement.

---

### Fix 4 — Alias de type `TranslationFunc` sur toutes les signatures de check (`bob/checks/_run.py`, 42 fichiers)

#### Problème

La fonction de traduction `t` était passée en argument nommé à toutes les fonctions `check_*` avec l'annotation `t=None` (non typée). Les vérificateurs de type ne pouvaient pas inférer la signature de l'appelable, et les IDEs n'offraient pas de complétion pour des appels comme `_t("clé", param=valeur)`. Il n'existait pas non plus de lieu unique pour documenter le contrat de la fonction.

#### Correction

`bob/checks/_run.py` (déjà importé par chaque module de check) gagne :

```python
from typing import Callable

TranslationFunc = Callable[..., str]
"""Type alias pour la fonction de traduction de BOB : t(key, **kwargs) -> str."""
```

Les 42 signatures de fonctions `check_*` dans 40 fichiers de checks, `bob/history.py` et `bob/plugin_checks.py` sont mises à jour :

```python
# Avant
def check_firewall(snapshot, *, t=None, ...):

# Après
def check_firewall(snapshot, *, t: TranslationFunc | None = None, ...):
```

Les deux occurrences restantes de `t=None` sont des fonctions auxiliaires privées (`_check_installed_kernels`, `_check_exposure`) où l'annotation ajouterait du bruit sans bénéfice.

---

### Fix 5 — `_has_shell_ops()` via tokenisation `shlex` (`bob/fixes.py`)

#### Problème

`_run_fix()` utilisait la correspondance par sous-chaîne pour décider si une commande de remédiation nécessitait `shell=True` :

```python
_SHELL_OPS = ("&&", "||", "|", ";", ">", ">>")

if any(op in cmd for op in _SHELL_OPS):
    subprocess.run(cmd, shell=True, ...)
else:
    subprocess.run(shlex.split(cmd), shell=False, ...)
```

`op in cmd` correspond partout dans la chaîne, y compris dans les arguments entre guillemets et les chemins de fichiers. Une commande avec un chemin contenant `>` ou un argument de type `--format=json>output` serait incorrectement routée vers `shell=True`, introduisant une surface d'injection shell inutile.

#### Correction

```python
def _has_shell_ops(cmd: str) -> bool:
    """Retourne True si cmd contient des opérateurs shell nécessitant shell=True."""
    _SHELL_TOKENS = frozenset({"&&", "||", ";", "|", ">", ">>", "<", "&"})
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return True   # guillemets malformés — traité comme non sûr
    return any(tok in _SHELL_TOKENS or tok.startswith("`") or tok.startswith("$(")
               for tok in tokens)
```

`shlex.split()` tokenise la commande comme le ferait un shell POSIX, en retirant les guillemets sans rien substituer. Les opérateurs ne sont correspondus qu'en tant que tokens complets. Les guillemets malformés retournent prudemment `True` plutôt que de lever une exception.

---

### Fix 6 — Fallback de profil maintenant visible (`bob/__main__.py`, locales)

#### Problème

`load_profile()` retournait silencieusement le profil `server` par défaut quand le nom de profil demandé n'était pas trouvé. Quand un utilisateur passait `--profile=laptop` (profil inexistant), l'audit s'exécutait avec le profil `server` sans aucune indication dans la sortie. L'utilisateur ne pouvait pas distinguer "profil actif" de "profil ignoré silencieusement".

#### Correction

```python
active_profile = load_profile(profile_name)
if profile_name not in ("", "default", "server") and active_profile.name != profile_name:
    output.print_warn(t("audit.profile_not_found", profile=profile_name))
```

La garde exclut les alias du profil par défaut (`""`, `"default"`, `"server"`) pour éviter les avertissements parasites quand aucun profil n'est spécifié. Nouvelles clés i18n :

- `en.json` : `"profile_not_found": "Profile '{profile}' not found — using default (server)"`
- `fr.json` : `"profile_not_found": "Profil '{profile}' introuvable — utilisation du profil par défaut (server)"`

---

### Tests

4274/4274 (+12 nouveaux, tous verts) :

| Fichier | Tests ajoutés |
|---------|--------------|
| `tests/test_kernel_modules.py` | `test_up_to_date_names_running_kernel_not_unsigned_sibling` — asserte le nom du kernel courant dans le message OK, pas le sibling `-unsigned` |
| `tests/test_kernel_modules.py` | `test_debian_signed_unsigned_pair_uses_obsolete_same_message` — asserte la clé `kernels_obsolete_same` quand une paire signé/non-signé est au sommet |
| `tests/test_compare.py` | `test_variable_deductions_increased_shown_without_structural_change` |
| `tests/test_compare.py` | `test_variable_deductions_decreased_shown_without_structural_change` |
| `tests/test_compare.py` | `test_variable_deductions_suppressed_when_warn_delta` |
| `tests/test_compare.py` | `test_variable_deductions_suppressed_when_new_finding_key` |
| `tests/test_compare.py` | `test_deduction_total_none_in_new_baseline_defaults` — le défaut de `AuditBaseline()` est `None` |
| `tests/test_compare.py` | `test_load_baseline_returns_none_when_field_absent` — ancien JSON sans champ → `None` |
| `tests/test_compare.py` | `test_load_baseline_returns_int_when_field_present` — nouveau JSON avec champ → entier |
| `tests/test_compare.py` | `test_deduction_delta_zero_when_prev_is_old_baseline` — prev `None` → delta = 0 |
| `tests/test_compare.py` | `test_deduction_delta_computed_when_both_tracked` — deux entiers → delta correct |
| `tests/test_compare.py` | `test_deduction_delta_zero_when_unchanged` — même valeur des deux côtés → 0 |

---

## [v0.2.3] — 03-05-2026

Huit corrections identifiées lors d'une tournée d'audit multi-VM systématique (Linux Mint desktop, Debian 13, Kali, VM Linux Mint, Ubuntu 26.04). Trois corrections comportementales dans la couche de vérification, deux corrections infrastructure, et trois corrections de précision UX trouvées par comparaison multi-distros. Aucune nouvelle fonctionnalité. 4262/4262 tests (+1).

---

### Fix 1 — NOT_LISTENING toujours INFO (`bob/checks/services.py`, `tests/test_services.py`)

#### Problème

`_check_exposure()` dans `services.py` comportait une branche conditionnelle sur la sévérité pour `Exposure.NOT_LISTENING` :

```python
elif exposure == Exposure.NOT_LISTENING:
    if snap.service.is_high_or_critical:
        result.warn(message=port_msg, nature="improvement")
    else:
        result.info(message=port_msg)
```

Pour les services CRITIQUE/ÉLEVÉ (ex. Mosquitto, Redis, SSH) avec un port enregistré mais non lié activement, cela produisait un finding `⚠ [ATTENTION]` avec `nature="improvement"`. Ce finding apparaissait dans la boîte résumé sous "⚠ Améliorations possibles", alors qu'un port qui n'écoute pas est un état neutre — le service n'expose pas le port, ce qui est favorable.

Trouvé sur : Linux Mint desktop (Telnet NOT_LISTENING dans le résumé malgré l'absence d'installation) et VM Linux Mint (Mosquitto 8883 en WARN alors que seul 1883 était lié).

#### Correction

```python
elif exposure == Exposure.NOT_LISTENING:
    result.info(message=port_msg)
```

La branche conditionnelle sur la sévérité est supprimée. `NOT_LISTENING` est informationnel sur tous les services.

---

### Fix 2 — Dominance locale IoT : déduction supprimée (`bob/checks/logs.py`, `tests/test_logs.py`)

#### Problème

`_check_local_dominance()` détecte quand une seule IP privée domine les logs UFW bloqués — pattern causé par des appareils IoT diffusant en UDP sur le réseau local. Précédemment :

```python
result.warn(
    message=_t("logs.local_dominance", ...),
    key="logs.local_dominance",
    nature="improvement",
)
result.add_deduction(
    reason=_t("deduction.local_dominance", ...),
    points=1,
    key="logs.local_dominance",
)
```

Déduire 1 point pour du trafic IoT bénin était incorrect. La fonction identifiait déjà la source comme une adresse privée et la qualifiait de pattern faible sévérité ; pénaliser le score était contradictoire.

Trouvé sur : Linux Mint desktop (score inférieur aux attentes ; diffusion IoT d'une prise connectée réduisant le score de 1 pt).

#### Correction

```python
result.info(
    message=_t("logs.local_dominance", ...),
    key="logs.local_dominance",
)
```

Rétrogradé en `result.info()`, sans déduction. Le message informatif reste visible dans l'audit complet.

---

### Fix 3 — Heredoc non tronqué (`bob/display.py`)

#### Problème

`_add_finding_lines()` passait la chaîne `item.cmd` entière à `_wrap_for_box()` :

```python
for content, val in _wrap_for_box(cmd_prefix, item.cmd, inner):
    lines.append(...)
```

`_wrap_for_box()` appelle `text.split()` en interne, qui découpe sur tous les espaces blancs y compris `\n`. Les commandes multi-lignes (blocs heredoc dans les étapes de remédiation auditd) étaient fusionnées en une seule ligne continue, les rendant illisibles.

Trouvé sur : Linux Mint desktop (bloc heredoc auditd affiché sur une seule ligne dans la boîte résumé).

#### Correction

```python
cont_prefix = " " * len(cmd_prefix)
for i, cmd_line in enumerate(item.cmd.splitlines()):
    pfx = cmd_prefix if i == 0 else cont_prefix
    for content, val in _wrap_for_box(pfx, cmd_line, inner):
        lines.append((f"{_oc.violet_bold}{content}{_oc.reset}", val))
```

Chaque ligne de `item.cmd` est traitée indépendamment par `_wrap_for_box()`. Les lignes de continuation utilisent un préfixe aligné (indenté pour correspondre au marqueur `→ ` ou `ℹ ` de la première ligne).

---

### Fix 4 — Garde contre les symlinks circulaires dans `--install-completion` (`bob/completion.py`)

#### Problème

`_install_completion()` vérifiait :

```python
candidate = home / ".local" / "bin" / "bob"
if candidate.exists():
    bin_src = candidate
```

Quand pipx était installé en root (`/usr/local/bin/bob`) et que `--install-completion` était exécuté en tant qu'utilisateur, `~/.local/bin/bob` était déjà un symlink pointant vers le binaire système. L'utiliser comme `bin_src` amenait l'installeur de completion à créer un nouveau symlink au même chemin pointant vers lui-même, produisant une chaîne circulaire (`~/.local/bin/bob → lui-même`).

Trouvé sur : desktop de l'utilisateur après `--install-completion` ; `pipx upgrade` affichait ensuite un avertissement de symlink circulaire.

#### Correction

```python
if candidate.exists() and candidate.resolve() != dst_bin.resolve():
    bin_src = candidate
```

`resolve()` suit tous les symlinks jusqu'au chemin canonique. Si `candidate` et `dst_bin` se résolvent vers le même chemin, le candidat est ignoré et le binaire système est utilisé directement. `exists()` retourne déjà `False` pour les symlinks cassés ou circulaires, donc la vérification combinée couvre tous les cas d'échec.

---

### Fix 5 — Python 3.9 retiré (`pyproject.toml`, `.github/workflows/tests.yml`, `.github/workflows/publish.yml`)

#### Problème

Python 3.9 a atteint sa fin de vie en octobre 2025. `Path.stat()` n'accepte pas `follow_symlinks` en argument nommé avant Python 3.10, causant une `TypeError` dans `tests/test_manage_logs.py` sur le runner CI 3.9.

#### Correction

- `requires-python = ">=3.10"` dans `pyproject.toml` (était `">=3.9"`).
- Classifier Python 3.9 supprimé de `pyproject.toml`.
- Matrice CI dans `tests.yml` et `publish.yml` passée de `["3.9", "3.10", "3.12"]` à `["3.10", "3.12"]`.

---

### Fix 6 — Compare : delta de déductions variables (`bob/compare.py`, locales)

#### Problème

`AuditBaseline` stockait `score`, `alert_count`, `warn_count` et `finding_keys`, mais pas le total des points de déduction bruts. Quand le score changeait entre deux audits sans changement structurel (mêmes clés de findings, mêmes counts alertes/warns — ex. parce que les déductions basées sur les logs variaient avec l'activité réseau), `display_delta()` affichait uniquement :

```
⚠ Score dégradé de N point(s)
```

sans autre explication, empêchant l'utilisateur de comprendre pourquoi le score avait bougé.

Trouvé sur : VM Debian 13 et VM Kali (delta de score sans explication structurelle).

#### Correction

`AuditBaseline` gagne `deduction_total: int = 0` (la valeur par défaut `0` permet le chargement des anciens baselines sans erreur). `AuditDelta` gagne `deduction_delta: int = 0`. `build_baseline()` calcule `sum(d.points for d in engine.breakdown)`. `load_baseline()` lit `raw.get("deduction_total", 0)`.

`display_delta()` affiche le message de déductions variables quand :
- `deduction_delta != 0`, ET
- aucune explication structurelle n'existe (`alert_delta == 0`, `warn_delta == 0`, `new_finding_keys` vide, `resolved_finding_keys` vide).

Nouvelles clés i18n : `compare.variable_deductions_increased`, `compare.variable_deductions_decreased`.

---

### Fix 7 — Surface d'attaque : label SSH scindé (`bob/exposure.py`, locales, `tests/test_exposure.py`)

#### Problème

`compute_exposure()` utilisait une seule clé i18n pour deux états SSH distincts :

```python
if "ssh.not_installed" in all_keys or "ssh.not_active" in bad_keys:
    detail=t("exposure.ssh_not_running")  # "non installé / non démarré"
```

Quand SSH était installé mais son service arrêté (ex. Kali Linux, où `sshd` est intentionnellement inactif), le tableau de surface d'attaque affichait "non installé / non démarré" — factuellement incorrect, le paquet étant présent.

Trouvé sur : VM Kali (SSH installé mais arrêté ; label indiquait "non installé").

#### Correction

```python
if "ssh.not_installed" in all_keys:
    detail=t("exposure.ssh_not_installed")   # "non installé"
elif "ssh.not_active" in bad_keys:
    detail=t("exposure.ssh_stopped")          # "installé — non démarré"
```

La clé `ssh_not_running` est remplacée par deux clés distinctes : `ssh_not_installed` et `ssh_stopped`. Nouveau test : `test_not_active_shows_stopped_text`.

---

### Fix 8 — Services : message `active_disabled` avec label du service (`bob/checks/services.py`, locales)

#### Problème

Quand un service était actif mais non activé au démarrage (`ServiceState.ACTIVE_DISABLED`), le message de finding était :

```
"Le service est actif en ce moment, mais ne redémarrera pas automatiquement."
```

Dans l'audit complet, ce message était contextuellement clair (il apparaissait sous l'en-tête de section `▶ NomDuService`). Dans la boîte résumé, le nom du service était absent, empêchant l'utilisateur d'identifier quel service était concerné sans parcourir l'audit complet.

Trouvé sur : VM Linux Mint (Redis actif mais non activé ; boîte résumé affichait le message sans "Redis").

#### Correction

Chaîne i18n : `"{label} est actif en ce moment, mais ne redémarrera pas automatiquement."` (FR et EN mis à jour). Site d'appel : `_t("services.state.active_disabled", label=snap.label)`.

---

### Tests

4262/4262 (+1 nouveau, 4 renommés/mis à jour) :

| Fichier | Modification |
|---------|-------------|
| `tests/test_services.py` | `test_not_listening_critical_adds_warn` → `_adds_info` · `test_not_listening_high_adds_warn` → `_adds_info` · assertions changées en `has_level(result, "info")` et `not has_level(result, "warn")` |
| `tests/test_logs.py` | `test_finding_is_warn_level` → `test_finding_is_info_level` (asserte `FindingLevel.INFO`) · `test_score_deduction_one_point` → `test_no_score_deduction` (asserte `len(local_deductions) == 0`) |
| `tests/test_exposure.py` | `test_not_installed_info_is_ok` et `test_not_installed_overrides_password_auth` assertent la clé `exposure.ssh_not_installed` · +1 `test_not_active_shows_stopped_text` asserte la clé `exposure.ssh_stopped` |

---

## [v0.2.2] — 03-05-2026

Cinq corrections ciblées du scoring, un fix de locale, une passe d'uniformisation du logging sur trois modules, une correction du check de règle UFW sans protocole, une correction du plafond de domaine (UFW inactif), des tests d'invariants scoring et une documentation de la pondération égale des domaines. 4261/4261 tests (+23).

---

### Fix 1 — Propagation `ScoreCap.key` (`bob/scoring.py`, `bob/checks/firewall.py`)

#### Problème

`ScoreCap` n'avait pas de champ `key`. Quand un plafond se déclenchait, `finalize()` ajoutait une `Deduction` synthétique dans `engine.breakdown` avec `key=""` :

```python
self.breakdown.append(
    Deduction(reason=self._cap.reason, points=delta, context="structural")
)
```

`compute_domain_scores()` ignore les déductions avec `key=""` (`_key_to_domain()` retourne `None` pour les clés vides). Un plafond pare-feu-inactif qui réduisait le score de plusieurs points contribuait zéro aux déductions du domaine `firewall` — le plafond était invisible au scoring par domaine.

#### Correction

`ScoreCap` gagne `key: str = ""` :

```python
@dataclass
class ScoreCap:
    maximum: int
    reason:  str
    key:     str = ""
```

`CheckResult.set_cap()`, `ScoreEngine.cap()` et `ScoreEngine.apply()` propagent tous la clé. `finalize()` utilise `self._cap.key` dans la déduction synthétique :

```python
self.breakdown.append(
    Deduction(reason=self._cap.reason, points=delta, context="structural", key=self._cap.key)
)
```

`bob/checks/firewall.py` mis à jour :

```python
result.set_cap(maximum=3, reason=_t("firewall.inactive"), key="firewall.inactive")
```

---

### Fix 2 — Les findings INFO n'inflatent plus l'ensemble des domaines actifs (`bob/domain_scores.py`)

#### Problème

`active_domains_from_engine()` itérait sur tous les findings sans distinction de niveau :

```python
for finding in engine.findings:
    domain = _key_to_domain(finding.key)
    if domain:
        active.add(domain)
```

Un domaine INFO-only — service installé sans aucun problème actionnable (ex. ClamAV installé, base fraîche, scan récent) — était inclus dans `active_domains` et donc dans la moyenne globale. Cela pouvait soit diluer les scores des domaines réellement dégradés, soit gonfler la moyenne quand un domaine INFO-only avec un score élevé était inclus.

#### Correction

`FindingLevel` importé directement depuis `bob.scoring`. Les boucles de findings filtrent maintenant à WARN et ALERT uniquement :

```python
_actionable = (FindingLevel.WARN, FindingLevel.ALERT)
for finding in engine.findings:
    if finding.level not in _actionable:
        continue
    domain = _key_to_domain(finding.key)
    if domain:
        active.add(domain)
```

La boucle des déductions reste inchangée — un domaine avec des déductions mais sans finding WARN/ALERT (cas limite) est toujours compté comme actif via le chemin déductions.

---

### Fix 3 — `clamav.db_very_outdated` 2pt → 1pt (`bob/checks/clamav.py`)

#### Problème

`check_clamav()` émettait une déduction de 2 points pour `clamav.db_very_outdated` (base de données ≥ 30 jours). L'entrée `clamav` dans `_TOOL_CAPS` plafonne la contribution de l'outil à 1 point par domaine. Le deuxième point n'affectait que `engine._raw_score` avant la moyenne par domaine, créant une asymétrie silencieuse : le score brut pénalisait ce finding deux fois plus fort que le score par domaine.

#### Correction

```python
# avant
result.add_deduction(
    reason=_t("clamav.db_very_outdated", days=snapshot.db_age_days),
    points=2, context="local", key="clamav.db_very_outdated",
)

# après
result.add_deduction(
    reason=_t("clamav.db_very_outdated", days=snapshot.db_age_days),
    points=1, context="local", key="clamav.db_very_outdated",
)
```

Total de déductions ClamAV en pire cas : `freshclam:1 + db_very_outdated:1 + scan_very_old:1 = 3` (était 4).

---

### Observabilité — logging uniformisé (`bob/history.py`, `bob/ignore.py`, `bob/sysinfo.py`)

Six gestionnaires `except … pass` remplacés par `_log.debug()`. `import logging` et `_log = logging.getLogger(__name__)` ajoutés aux trois modules. Les échecs restent non-fatals ; visibles avec `--debug`.

#### `bob/history.py`

```python
# save_score() — avant
except OSError:
    pass

# save_score() — après
except OSError as exc:
    _log.debug("Failed to save score to history: %s", exc)

# _rotate_if_needed() — avant
except OSError:
    pass

# _rotate_if_needed() — après
except OSError as exc:
    _log.debug("Failed to rotate history file: %s", exc)
```

#### `bob/ignore.py`

```python
# load_ignore_keys() — avant
except OSError:
    pass

# load_ignore_keys() — après
except OSError as exc:
    _log.debug("Cannot read ignore file %s: %s", path, exc)
```

#### `bob/sysinfo.py`

`get_user_home()` : SUDO_USER défini mais absent de la base de données des mots de passe — le repli sur `Path.home()` est maintenant loggé, ce qui explique les chemins de configuration inattendus lors de l'exécution avec des configurations sudo exotiques.

`collect_system_info()` : l'échec de lecture de `/etc/os-release` est maintenant loggé.

`detect_network_type()` : les deux échecs subprocess (`ip route` et `ip addr`) sont maintenant loggés. Auparavant, ces échecs silencieux faisaient tomber la fonction sur `get_public_ip()` sans aucune trace.

```python
# detect_network_type() — avant (deux emplacements)
except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
    pass

# detect_network_type() — après
except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
    _log.debug("ip route failed during network type detection: %s", exc)
    # (et séparément pour ip addr)
    _log.debug("ip addr failed during network type detection: %s", exc)
```

---

### Contrat scoring documenté (`bob/scoring.py`)

Docstring de `ScoreEngine.finalize()` mise à jour :

```
Required call sequence (orchestrator contract):
    engine.finalize()
    apply_domain_score_override(engine)   # from bob.domain_scores

After finalize() but before apply_domain_score_override(), engine.score
returns the raw deduction-based score.  The domain-averaged global score
is only available after apply_domain_score_override() sets the override.
```

Docstring de `ScoreEngine.set_global_score()` mise à jour :

```
Do not call this directly — use apply_domain_score_override(engine)
from bob.domain_scores, which computes the correct domain average.
The raw pre-override score remains accessible as engine._raw_score.
```

---

### Fix 4 — Plafond de domaine non appliqué si le score brut global est déjà sous le seuil (`bob/domain_scores.py`)

`compute_domain_scores()` calcule le score de chaque domaine en sommant les déductions de `engine.breakdown` qui lui correspondent. Lorsqu'un plafond se déclenche (ex. `firewall.inactive` → max 3/10), `finalize()` ajoute un delta de déduction dans `breakdown` **uniquement si** `_raw_score > cap.maximum`. Sur un système cumulant beaucoup de déductions (pare-feu + durcissement + …), le score brut global peut déjà être sous le seuil du plafond — le delta n'est jamais ajouté, le score du domaine cible reste à sa valeur brute pré-plafond (ex. 6/10 au lieu de 3/10 pour le pare-feu quand UFW est inactif). La note « Score plafonné à 3 » s'affiche quand même (elle lit `engine.cap_info` enregistré, indépendamment du déclenchement). Correction : `compute_domain_scores()` lit maintenant `engine.cap_info` et, si sa clé correspond à un domaine, applique directement le plafond sur le total de déductions de ce domaine. Le fix est idempotent. Trouvé sur une VM Ubuntu 26.04 avec UFW inactif et plusieurs problèmes de durcissement.

### Fix 5 — Check de règle orpheline manquant les règles UFW sans protocole (`bob/checks/firewall.py`)

`_check_orphan_rules()` analysait le champ « To » d'UFW avec `_PORT_PROTO_RE` qui exige un suffixe de protocole explicite (`/tcp` ou `/udp`). Une règle écrite en numéro de port nu — syntaxe UFW valide signifiant « appliquer à TCP et UDP » — produisait `m = None` et tombait dans `continue`. En pratique, `57621 ALLOW IN 192.168.1.0/24` (Spotify Connect) coexistait avec `41681/tcp ALLOW IN 192.168.1.0/24`. BOB signalait correctement `41681/tcp` comme règle orpheline mais ignorait silencieusement `57621`. Nouveau `_PORT_BARE_RE` gère ce cas de repli. Trouvé en exécutant l'outil sur une machine réelle.

### Fix 6 — Locale SSH : commande dupliquée dans le bloc « Que faire ? » (`bob/locales/fr.json`, `bob/locales/en.json`)

`ssh.not_active_detail` contenait la commande de remédiation (`"Activer avec : sudo systemctl enable --now ssh"`). Le moteur d'affichage rendant à la fois le `detail` et le `cmd` sous forme de lignes `→`, le bloc « Que faire ? » affichait deux fois la même commande. Le champ `detail` est destiné au contexte (pourquoi agir), pas à la commande (qui appartient à `cmd`). Corrigé par un texte explicatif sans commande : `"Le service est désactivé — activez-le si l'accès SSH est nécessaire."` Trouvé sur Kali Linux où SSH est installé mais intentionnellement arrêté.

### Tests d'invariants scoring (`tests/test_scoring.py`, `tests/test_domain_scores.py`)

Classes `TestScoringInvariants` ajoutées aux deux fichiers de test — 12 nouveaux tests pour les propriétés structurelles devant tenir quel que soit l'input. C'est la couche de tests de propriétés du pipeline de scoring, couvrant la monotonie, les bornes et la sémantique d'activation.

#### `tests/test_scoring.py` — `TestScoringInvariants` (+5)

Invariants du moteur de scoring : score plancher (0), plafond (MAX), monotonie des déductions, plafond supérieur sans effet, override domaine dans la plage.

#### `tests/test_domain_scores.py` — `TestScoringInvariants` (+7)

Points clés :

- **INFO-only → domaine inactif :** un finding `level=INFO` sans déduction ne marque pas le domaine comme « actif » pour la moyenne globale.
- **WARN/ALERT → domaine actif :** ces niveaux activent bien le domaine, même sans déduction associée.
- **Déduction seule active :** `add_deduction(key=...)` sans finding active quand même le domaine via le chemin déductions dans `active_domains_from_engine()`.
- **Moyenne globale bornée :** résultat de `compute_global_from_domains` toujours `≥ min(scores_actifs)` et `≤ max(scores_actifs)`.
- **Scores dans la plage :** `compute_domain_scores` produit toujours des valeurs dans `[0, MAX_SCORE]` pour chaque domaine.

Le test d'activation par déduction seule est particulièrement important : il confirme que `active_domains_from_engine()` vérifie à la fois le chemin findings (filtre WARN/ALERT) et le chemin déductions (sans filtre), et que cette asymétrie est intentionnelle.

### Tests

4261/4261 (+23 nouveaux, 2 mis à jour) :

#### `tests/test_domain_scores.py` — `TestEngineLevelDomainCap` (+6)

Six nouveaux cas dans une nouvelle classe couvrant le fix du plafond de domaine : plafond appliqué avec peu de déductions · plafond appliqué quand le score brut global est déjà sous seuil (delta absent du breakdown) · pas de sur-plafonnement si déjà au cap · score ne dépasse jamais le plafond · pas de saignement vers d'autres domaines · tous scores dans la plage.

#### `tests/test_firewall.py` — `TestOrphanRules` (+3)

Trois nouveaux cas dans la classe `TestOrphanRules` existante : règle bare-port signalée si rien en écoute · non signalée si TCP en écoute · non signalée si UDP en écoute.

#### `tests/test_manage_logs.py` — `TestStatFallback` (+2)

Régression pour le fix race condition `.stat()` de v0.2.1. Les boucles d'affichage mode texte dans `_run_manage_logs_plain()` avaient été mises à jour en v0.2.1 pour envelopper `.stat()` dans `try/except OSError` — mais aucun test ne couvrait le chemin de repli.

Un helper `_stat_raises_for_logs` est défini au niveau module (capturé avant tout run de test) qui lève `OSError` uniquement pour les fichiers `.log`, en déléguant au vrai `Path.stat` pour les répertoires. C'est nécessaire car `Path.exists()` de Python 3.12 appelle `self.stat()` en interne — un mock global casserait `exists()` sur les répertoires et ferait échouer les tests.

```python
_real_path_stat = Path.stat

def _stat_raises_for_logs(self, *, follow_symlinks=True):
    if self.suffix == ".log":
        raise OSError("race: file disappeared between scan and display")
    return _real_path_stat(self, follow_symlinks=follow_symlinks)
```

| Test | Couverture |
|------|------------|
| `test_cur_logs_stat_oserror_uses_fallback` | `.stat()` lève dans la boucle `cur_logs` → `"(0 "` et `"?"` dans la sortie |
| `test_extra_logs_stat_oserror_uses_fallback` | `.stat()` lève dans la boucle `extra_sections` → idem |

#### `tests/test_clamav.py` (2 mis à jour)

| Test | Avant | Après |
|------|-------|-------|
| `test_db_very_outdated_deducts_1` (était `_deducts_2`) | vérifiait `pts == 2` | vérifie `pts == 1` |
| `test_worst_case` | vérifiait total == 4 | vérifie total == 3 |

---

## [v0.2.1] — 02-05-2026

Hotfix défensif — 17 améliorations ciblées identifiées par un audit dual-agent (passes indépendantes par Claude et Copilot). Aucune nouvelle fonctionnalité, aucun changement de comportement, aucun nouveau test. 4238/4238 inchangés.

### `bob/manage_logs.py` — correction de crash : `.stat()` non protégé en mode texte

#### Problème

Les boucles d'affichage mode texte dans `_run_manage_logs_plain()` appelaient `f.stat()` directement :

```python
size_kb = max(1, f.stat().st_size // 1024)
mtime = _dt.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
```

Si un fichier log était supprimé entre le scan du répertoire et la boucle d'affichage (ex. : `logrotate` en parallèle), cela levait `OSError` et plantait `--manage-logs`. Le mode curses (lignes 792–796) avait déjà la protection correcte :

```python
try:
    size_kb = max(1, f.stat().st_size // 1024)
    mtime   = _dt.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
except OSError:
    size_kb, mtime = 0, "?"
```

#### Correction

Les deux boucles du chemin mode texte (`cur_logs` et `extra_sections`) enveloppent maintenant `.stat()` de façon identique au mode curses, avec `(0, "?")` comme valeurs de repli.

---

### Resserrement des gestionnaires d'exceptions — 8 emplacements

Tous les `except Exception` (qui capturent aussi les erreurs de programmation et compliquent le débogage) remplacés par les types d'exceptions spécifiques pouvant réellement être levées.

#### `bob/cis_refs.py` — `_load()`

Lit et parse un fichier JSON. Seuls échecs possibles : I/O (`OSError`) et JSON malformé (`json.JSONDecodeError`).

```python
# avant
except Exception:
    return {}

# après
except (OSError, json.JSONDecodeError):
    return {}
```

#### `bob/manage_logs.py` — `_get_extra_dirs()`

Parse une liste de chaînes encodée en JSON depuis la config utilisateur. Échecs : JSON malformé, types de valeurs inattendus.

```python
# avant
except Exception:
    return []

# après
except (json.JSONDecodeError, ValueError, TypeError):
    return []
```

#### `bob/manage_logs.py` + `bob/explain.py` + `bob/cron.py` — replis curses

Trois appels `curses.wrapper()` qui reviennent au mode texte en cas d'échec terminal. `curses.error` couvre tous les échecs d'initialisation et de rendu terminal ; `OSError` couvre les erreurs I/O niveau terminal.

```python
# avant (les trois sites)
except Exception:
    return _run_*_plain(...)

# après
except (curses.error, OSError):          # manage_logs.py, explain.py
    return _run_*_plain(...)

except (_curses.error, OSError):         # cron.py (curses importé comme _curses)
    return _run_*_plain(...)
```

#### `bob/checks/ssh.py` — parsing binaire des clés

`_rsa_bits_from_blob()` : décode du base64 et dépaquète un format binaire SSH. Échecs : base64 invalide (`binascii.Error`, sous-classe de `ValueError`) et struct malformé (`struct.error`).

```python
# avant
except Exception:
    return None

# après
except (struct.error, ValueError):
    return None
```

`_has_passphrase()` : décode des données base64 de clé OpenSSH. Seul `binascii.Error` (base64 invalide, sous-classe de `ValueError`) peut être levé dans le bloc try.

```python
# avant
except Exception:
    return None

# après
except (binascii.Error, ValueError):
    return None
```

`import binascii` ajouté en tête de `ssh.py`.

---

### Regex déplacées en module-level — 3 fichiers

Les patterns `re.compile()` définis dans les corps de fonctions — recompilés à chaque appel — déplacés en constantes module. Python ne met pas en cache les résultats de `re.compile()` appelés dans des fonctions.

#### `bob/checks/firewall.py`

```python
_OPEN_ANY_RE = re.compile(
    r"Anywhere(?:/\w+)?(?:\s+\(v6\))?\s+ALLOW\s+IN\s+Anywhere(?:/\w+)?(?:\s+\(v6\))?\s*$",
    re.IGNORECASE,
)
_ALLOW_IN_RE   = re.compile(r"\bALLOW\s+IN\b", re.IGNORECASE)
_PORT_PROTO_RE = re.compile(r"\b(\d{1,5}/(?:tcp|udp))\b", re.IGNORECASE)
```

`_check_open_any()` et `_check_orphan_rules()` mis à jour pour référencer les constantes module.

#### `bob/checks/cron_audit.py`

```python
_PATH_RE = re.compile(r"(/[^\s;|&<>]+\.sh)\b")
```

Déplacé depuis l'intérieur de `_find_world_writable_scripts()` vers le module, aux côtés du `_PIPE_TO_SHELL_RE` existant.

#### `bob/checks/firmware.py`

```python
_FLAT_SKIP_RE = re.compile(
    r"^(Update|Version|Summary|Description|Requires|Urgency|Remote|Size|"
    r"Flags|Status|GUID|Device|AppStream|Release|\[|WARNING|Error|\s)",
    re.IGNORECASE,
)
```

Déplacé depuis l'intérieur de `_parse_fwupd_updates()` vers le module, aux côtés du `_TREE_ITEM_RE` existant.

---

### `bob/cron.py` — regex email dédupliqué

`_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")` était défini identiquement dans trois fonctions séparées : `_select_emails_plain()` (ligne 325), `_curses_email_list_sub()` (ligne 1273), `_curses_email_store_sub()` (ligne 1398). Déplacé en constante module unique (ligne 20). Le même pattern existe indépendamment dans `bob/config.py` pour la validation de config ; les deux sont intentionnellement conservés, chaque module possédant sa propre contrainte.

---

### `bob/manage_logs.py` — helper `_resolve_path()` extrait

```python
def _resolve_path(raw: str, default: Path) -> Path:
    """Expand, resolve and return *raw* as a Path, or *default* if empty."""
    return Path(raw).expanduser().resolve() if raw else default
```

Le one-liner `Path(raw).expanduser().resolve() if raw else default` apparaissait à deux endroits : dans le `return` de `_prompt_path()` et dans le flux de changement de répertoire. Les deux appellent maintenant `_resolve_path()`. Le commentaire de sécurité (`resolve() normalise les composants ".."…`) est conservé au premier site d'appel.

---

### `bob/domain_scores.py` — accès direct aux attributs

`active_domains_from_engine()` et `compute_domain_scores()` utilisaient `getattr(engine, "findings", [])`, `getattr(finding, "key", None)` et `getattr(deduction, "points", 0)` comme gardes défensifs. `ScoreEngine.__init__` initialise toujours `findings`, `ignored_findings` et `breakdown` comme listes vides ; `Finding` et `Deduction` sont des dataclasses avec `key` et `points` comme champs obligatoires. Les `getattr` masquaient une dérive potentielle de l'API au lieu de la faire remonter. Remplacés par accès direct dans tout le fichier.

---

### `bob/recurrence.py` — log debug sur échec de chargement

```python
# avant
except (OSError, json.JSONDecodeError, ValueError):
    pass

# après
except (OSError, json.JSONDecodeError, ValueError) as exc:
    _log.debug("Failed to load recurrence data from %s: %s", src, exc)
```

`import logging` et `_log = logging.getLogger(__name__)` ajoutés. Les échecs restent non-fatals (le suivi de récurrence est best-effort) mais remontent désormais avec le niveau de log `--debug`.

---

### `bob/__main__.py` — logging des échecs webhook

```python
# avant
except Exception as _exc:  # noqa: BLE001
    print(f"Warning: webhook failed: {_exc}", file=sys.stderr)

# après
except Exception as _exc:  # noqa: BLE001
    _log.warning("Webhook failed: %s", _exc)
    print(f"Warning: webhook failed: {_exc}", file=sys.stderr)
```

`import logging` et `_log = logging.getLogger(__name__)` ajoutés. Les échecs webhook sont maintenant capturés par le système de logging en plus de l'affichage stderr visible par l'utilisateur.

---

### Tests

4238/4238 — aucun nouveau test, aucun changement de comportement. Tous les tests existants passent sans modification.

---

## [v0.2.0] — 01-05-2026

Cinq améliorations trouvées lors de l'analyse des premiers lancements sur Ubuntu 26.04 LTS et Debian 13.

### `bob/scoring.py` + `bob/domain_scores.py` — refonte du scoring

#### Problème

Le score global était calculé comme `10 − somme(toutes_les_déductions)`. Sur Debian 13 avec 8 déductions de −1 chacune, cela produisait 2/10 CRITIQUE alors que SSH, pare-feu, mises à jour et permissions fichiers étaient tous parfaits. Le score ne représentait pas la posture de sécurité réelle de la machine.

Deux problèmes supplémentaires :
- **Double pénalité sur un même outil** — rkhunter émettant `rootkit.db_outdated` et `rootkit.no_scan` déduisait 2 points du score global pour une seule décision de configuration.
- **Déconnexion score global / scores de domaine** — les scores de domaine étaient calculés indépendamment mais le score global n'en était pas dérivé, créant une contradiction dans la sortie.

#### Correction 1 — Plafond par outil dans `compute_domain_scores()`

Nouveau dict `_TOOL_CAPS` dans `domain_scores.py` :

```python
_TOOL_CAPS: dict[str, int] = {
    "rootkit":        1,   # rkhunter/chkrootkit — âge base + âge scan
    "clamav":         1,   # ClamAV — âge base + fréquence scan
    "file_integrity": 1,   # AIDE/Tripwire — présence + fraîcheur
}
```

Lors de l'accumulation des déductions par domaine dans `compute_domain_scores()`, chaque préfixe d'outil est plafonné à sa contribution maximale. Une deuxième déduction de `rootkit.*` quand le plafond est atteint contribue 0 point au score du domaine. Les préfixes sans plafond (`hardening.*`, `ssh.*`, etc.) s'accumulent normalement.

#### Correction 2 — Score global = moyenne des scores de domaine actifs

Nouvelle fonction `compute_global_from_domains(domain_scores, active_domains) -> int` dans `domain_scores.py` :

```python
active = [d for d in DOMAINS if d in active_domains and d in domain_scores]
return max(0, min(MAX_SCORE, round(total / len(active))))
```

Nouvelle fonction `apply_domain_score_override(engine)` appelle `compute_domain_scores`, `active_domains_from_engine` et `compute_global_from_domains`, puis appelle `engine.set_global_score()` avec le résultat.

Nouvelle méthode `ScoreEngine.set_global_score(score: int)` stocke la valeur domain-averaged dans `_global_override`. La property `score` retourne `_global_override` quand définie, avec repli sur `_raw_score` sinon. Le score brut interne n'est jamais modifié — disponible à `engine._raw_score` pour le débogage.

`apply_domain_score_override(engine)` est appelé immédiatement après `engine.finalize()` dans `bob/__main__.py` et `bob/watch.py`.

#### Effet

Cas de référence Debian 13 (8 déductions, tous les autres domaines sains) :
- Avant : 2/10 CRITIQUE (somme brute)
- Après : 6/10 (hardening=4, disk=9, moyenne des 2 domaines actifs dans le scénario de test ; 9/10 en utilisation réelle avec SSH/pare-feu/mises à jour actifs à 10/10)

### `bob/cron.py` — détection MTA (`_detect_mta()`)

#### Problème

L'assistant cron vérifiait `shutil.which("mail")` et avertissait `'mail' non disponible — installez mailutils`. La livraison des emails dans `report_markdown.py` utilise `sendmail -t -f`, pas `mail`. La vérification testait le mauvais binaire et recommandait un paquet inutile.

#### Correction

Nouveau helper `_detect_mta() -> tuple[bool, str]` :

```python
def _detect_mta() -> tuple[bool, str]:
    import shutil
    if not shutil.which("sendmail"):
        return False, ""
    for name, check in [
        ("Postfix", lambda: Path("/etc/postfix/main.cf").exists()),
        ("Exim",    lambda: bool(shutil.which("exim4") or shutil.which("exim"))),
        ("msmtp",   lambda: bool(shutil.which("msmtp"))),
        ("ssmtp",   lambda: bool(shutil.which("ssmtp"))),
    ]:
        if check():
            return True, name
    return True, ""
```

Les deux points d'appel dans `_run_install_cron_plain` et `_run_install_cron_curses` utilisent désormais `_detect_mta()`. Quand un email est configuré :
- MTA trouvé : `✔ Transport mail : Postfix (sendmail disponible — les notifications seront envoyées)`
- MTA absent : `⚠ sendmail introuvable — les emails de notification ne seront pas envoyés. Installez : sudo apt install postfix  ou  sudo apt install msmtp-mta`

Les clés de locale `mail_missing` remplacées par `mta_missing` et `mta_found` dans `bob/locales/en.json` et `bob/locales/fr.json`.

### `bob/checks/kernel_modules.py` — faux positif kernel `-unsigned` Debian

#### Problème

Sur Debian avec Secure Boot activé, apt installe à la fois :
- `linux-image-6.12.74+deb13+1-amd64` — noyau signé (démarré quand Secure Boot est actif)
- `linux-image-6.12.74+deb13+1-amd64-unsigned` — variante non signée (même version, paquet différent)

`_check_installed_kernels()` triait tous les noyaux installés par `_kernel_sort_key()`. Les deux variantes produisent la même clé de tri numérique `(6, 12, 74, 0)`. Le tri stable de Python retombe alors sur l'ordre lexicographique, plaçant `-amd64-unsigned` après `-amd64`. `most_recent` était défini comme la variante unsigned, faisant évaluer `running != most_recent` à `True` — déclenchant un faux avertissement de redémarrage.

#### Correction

Nouveau helper `_strip_unsigned(version: str) -> str` :

```python
def _strip_unsigned(version: str) -> str:
    return version[:-len("-unsigned")] if version.endswith("-unsigned") else version
```

`reboot_pending` compare désormais les versions sans le suffixe :

```python
reboot_pending = running in kernels and _strip_unsigned(running) != _strip_unsigned(most_recent)
```

Une véritable différence de version (ex. `6.12.63+deb13-amd64` en cours d'exécution alors que `6.12.74+deb13+1-amd64` est installé) déclenche toujours correctement l'avertissement de redémarrage.

### Tests

- `tests/test_kernel_modules.py` — +6 tests :
  - `TestKernelRebootPending.test_no_reboot_pending_debian_signed_plus_unsigned_same_version`
  - `TestKernelRebootPending.test_reboot_still_pending_when_genuinely_newer_debian_kernel`
  - `TestStripUnsigned` — 4 tests unitaires pour `_strip_unsigned()`
- `tests/test_cron.py` — +6 tests dans `TestDetectMta` : sans sendmail, Postfix (via fichier config), Exim, msmtp, ssmtp, MTA inconnu
- `tests/test_scoring.py` — +6 tests dans `TestSetGlobalScore` : override remplace le brut, pas d'override par défaut, clamp au-dessus du max, clamp sous zéro, niveau reflète l'override, score brut inchangé
- `tests/test_domain_scores.py` — +14 tests :
  - `TestToolCaps` (7 tests) — rootkit/clamav/file_integrity plafonné à 1 ; préfixes sans plafond s'accumulent ; plafonds ne débordent pas entre outils ; déduction partielle respecte le plafond
  - `TestComputeGlobalFromDomains` (4 tests) — moyenne, domaines vides, clamp max, clamp zéro
  - `TestApplyDomainScoreOverride` (3 tests) — override appliqué, plage valide, scénario Debian 13
- **Total : 4238 tests** (4206 → 4238, +32)

### `bob/checks/logs.py` — dominance IoT dans les logs : WARN −1 pt

#### Problème

Quand une seule IP privée représentait ≥ 70 % du trafic UFW bloqué sur ≥ 50 entrées, BOB émettait un finding `INFO` sans déduction de score. La fonctionnalité était documentée comme WARN −1 pt dans README_TECH.md, mais l'implémentation appelait `result.info()` sans `add_deduction()` — la déduction n'était jamais appliquée.

Découvert lors du premier test local sur `so6desktop` : `192.168.1.50` représentait 2267/2415 blocages (93 %) sans WARN ni déduction émis.

#### Correction

`bob/checks/logs.py` :
```python
result.warn(
    message=_t("logs.local_dominance", ip=local_ip, count=local_count,
               total=snapshot.total, pct=local_pct),
    key="logs.local_dominance",
    nature="improvement",
)
result.add_deduction(
    reason=_t("deduction.local_dominance", ip=local_ip, pct=local_pct),
    points=1,
    key="logs.local_dominance",
)
```

Nouvelle clé `deduction.local_dominance` ajoutée dans `bob/locales/en.json` et `bob/locales/fr.json`.

Trois tests existants dans `tests/test_logs.py` corrigés pour vérifier le comportement désormais correct :
- `test_check_logs_emits_warn_finding` (était `test_check_logs_emits_info_finding`)
- `test_finding_is_warn_level` (était `test_finding_is_info_level`)
- `test_score_deduction_one_point` (était `test_no_score_deduction`)

Total des tests inchangé : 4238.

### `bob/output.py` — bannière ASCII orange

L'art ASCII `BOB` affiché dans la bannière terminal est maintenant rendu en orange bold (`_c.orange_bold` = `\033[1;38;5;208m`). Les caractères de bordure (`║`, `╔`, `╠`, `╚`) conservent leur couleur bleu bold existante. Aucun impact sur les formats de sortie ni sur les fichiers de log — rendu terminal uniquement.

---

## [v0.1.1] — 29-04-2026

Hotfix. Trois corrections ciblées trouvées lors des premiers lancements sur Ubuntu 26.04 LTS et Debian 13.

### Corrections

#### `bob/checks/firmware.py` — parser fwupd 1.9+ format arbre

`fwupdmgr get-updates` a changé son format de sortie dans fwupd 1.9+ (livré avec Ubuntu 26.04 LTS). L'ancien parser supposait des noms d'appareils en colonne 0 avec les métadonnées indentées ; le nouveau format utilise une structure en arbre :

```
QEMU Ubuntu 24.04 PC (Q35 + ICH9, 2009)
│
├─UEFI CA:
│   Nouvelle version : 2024.01
│
└─QEMU DVD-ROM:
    Nouvelle version : 2.5
```

L'ancien `_parse_fwupd_updates()` capturait `│` et `├─UEFI CA:` comme noms d'appareils, produisant une sortie corrompue : `10 mise(s) à jour firmware en attente : QEMU Ubuntu 24.04 PC (Q35 + ICH9, 2009), │, ├─UEFI CA: (+7)`.

Correction : détection automatique du format arbre (présence de lignes `├─`/`└─`) ; en mode arbre, les noms d'appareils sont extraits uniquement depuis les lignes `├─`/`└─` en supprimant le préfixe et les deux-points finaux ; les lignes `│` et les lignes de conteneur parent sont ignorées. Le format plat reste inchangé.

Nouvelle constante de module : `_TREE_ITEM_RE = re.compile(r"^[├└]─\s*")`.

#### `bob/__main__.py` — message d'erreur `--install-completion`

Lorsque `bob --install-completion` est lancé sans root, le message d'erreur affichait la bonne commande avec le chemin complet (`sudo /chemin/vers/bob --install-completion`), mais les utilisateurs tapaient naturellement `sudo bob --install-completion` à la place, ce qui échoue car le PATH restreint de sudo n'inclut pas le `~/.local/bin` de pipx.

Le nouveau message explique explicitement que `sudo bob` ne fonctionnera pas (restriction PATH pipx) et invite à copier-coller la commande exacte affichée.

#### `bob/locales/en.json`, `bob/locales/fr.json` — en-tête de colonne du panorama des services

`services.panorama.header_ufw` : `"UFW"` → `"SCOPE"` (EN) / `"PORTÉE"` (FR).

La colonne utilise `Exposure.OPEN_WORLD` pour déterminer l'indicateur — elle reflète si un service a une exposition de portée internet, pas si une règle UFW active le couvre. Avec UFW inactif, les services à portée LAN (Avahi, CUPS) affichaient correctement `✔` mais le label `UFW` suggérait une protection pare-feu active. Le nouveau label élimine cette ambiguïté.

### Tests

- `tests/test_firmware.py` — 4 nouveaux tests de régression couvrant le parser format arbre :
  - `test_tree_format_extracts_device_names` — les lignes `├─`/`└─` produisent les bons noms d'appareils
  - `test_tree_format_excludes_container_line` — le conteneur parent n'est pas capturé
  - `test_tree_format_excludes_tree_connectors` — les caractères `│`, `├`, `└` sont absents des résultats
  - `test_tree_format_strips_trailing_colon` — les noms extraits de `├─Nom:` ne conservent pas les deux-points
- **Total : 4206 tests** (4202 → 4206, +4)

---

## [v0.1.0] — 26-04-2026

Version initiale de BOB — Bodyguard Of Bits.

### Architecture

- **Module** `bob/` — package Python ; point d'entrée CLI `bob` via `bob.__main__:main`
- **46 vérifications** organisées en 9 domaines de sécurité ; chaque vérification produit des objets `Finding` typés consommés par le moteur de scoring
- **Moteur de scoring** (`bob/scoring.py`) — déductions pondérées par résultat, clampées 0–10 ; 5 sous-scores par domaine (firewall, ssh, hardening, updates, file_perms)
- **i18n** (`bob/i18n.py`, `bob/locales/en.json`, `bob/locales/fr.json`) — toutes les chaînes utilisateur externalisées ; `--french` / `-d` bascule la locale au runtime
- **Profils d'audit** (`bob/profiles.py`, `bob/data/profiles/`) — `server`, `workstation`, `desktop`, `docker` ; chaque profil déclare des surcharges de sévérité et des sections ignorées
- **API plugin** (`bob/plugin_checks.py`, `bob/registry.py`) — vérifications personnalisées via `~/.config/bob/checks.d/` ; définitions de services personnalisées via `~/.config/bob/services.d/`

### Vérifications de sécurité

#### Pare-feu
- `bob/checks/firewall.py` — règles UFW : règles dupliquées, règles open-any, couverture IPv6, conscience de la politique par défaut deny
- `bob/checks/iptables_nftables.py` — CHECK 46 : audit iptables/nftables quand UFW est inactif ; politique INPUT/FORWARD/OUTPUT ; détection conntrack ; analyse du ruleset nftables
- `bob/checks/ipv6.py` — cohérence IPv6 entre les règles UFW et sysctl
- `bob/checks/firewall_stack.py` — détection de la pile pare-feu (UFW/iptables/nftables/aucun) ; pile active affichée dans le banner
- `bob/checks/ports.py` — analyse d'exposition des ports : public vs LAN vs loopback ; identification des services ; filtrage des ports éphémères

#### SSH
- `bob/checks/ssh.py` — PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords, X11Forwarding, MaxAuthTries, ClientAliveInterval, UsePAM, AllowTcpForwarding, qualité des algorithmes de clés, ListenAddress, Banner

#### Durcissement noyau
- `bob/checks/kernel_hardening.py` — 20+ paramètres sysctl (net.ipv4/ipv6, fs.*, kernel.*) ; randomize_va_space, dmesg_restrict, kptr_restrict, ptrace_scope, etc.
- `bob/checks/kernel_modules.py` — modules filesystem et réseau à risque (cramfs, freevxfs, jffs2, hfs, udf, dccp, sctp, rds, tipc)
- `bob/checks/secure_boot.py` — état du Secure Boot via mokutil/efibootmgr
- `bob/checks/firmware.py` — mises à jour fwupd en attente ; présence des paquets microcode

#### Services
- `bob/checks/services.py` — 32 services connus avec classification du risque ; écoute sur les ports attendus ; contexte de risque affiché par service actif
- `bob/checks/services_state.py` — audit des services systemd activés+actifs ; CRITICAL/HIGH installé-mais-inactif → avertissement
- `bob/checks/docker.py` — détection de l'installation Docker ; contournement pare-feu UFW via la chaîne iptables DOCKER
- `bob/checks/docker_audit.py` — durcissement daemon.json ; conteneurs privilégiés ; network/pid/ipc hôte ; montages sensibles ; no-new-privileges
- `bob/checks/smtp.py` — exposition serveur SMTP ; inet_interfaces ; risque open relay

#### Permissions fichiers
- `bob/checks/file_perms.py` — fichiers world-writable ; permissions /etc/passwd /etc/shadow /etc/sudoers
- `bob/checks/suid_audit.py` — audit SUID/SGID avec liste blanche ; racines ciblées pour la performance

#### Comptes utilisateurs
- `bob/checks/user_accounts.py` — comptes expirés (UID≥1000) ; comptes verrouillés avec connexions récentes
- `bob/checks/password_policy.py` — /etc/login.defs (PASS_MAX_DAYS, PASS_MIN_DAYS, PASS_WARN_AGE) ; PAM pam_cracklib/pam_pwquality ; historique de mots de passe PAM
- `bob/checks/umask.py` — umask système (/etc/profile, /etc/bash.bashrc, /etc/login.defs)

#### Système
- `bob/checks/updates.py` — mises à jour de sécurité apt en attente (−2 flat) ; mises à jour régulières (INFO) ; unattended-upgrades compound (−1) ; vérification apt du noyau
- `bob/checks/logs.py` — niveau de journalisation UFW (off/low/medium/high/full)
- `bob/checks/log_rotation.py` — configuration logrotate ; taille /var/log/ufw.log ; rétention des logs
- `bob/checks/auth_log.py` — comptage des échecs de connexion depuis auth.log/journald ; patterns d'échecs répétés
- `bob/checks/ntp.py` — état de synchronisation NTP (systemd-timesyncd / chrony / ntpd)
- `bob/checks/fail2ban.py` — Fail2ban actif ; jail sshd activé
- `bob/checks/rootkit.py` — présence et âge du dernier scan rkhunter / chkrootkit
- `bob/checks/auditd.py` — auditd actif ; règles d'audit présentes ; règles clés (commandes privilégiées, modifications sudoers)
- `bob/checks/file_integrity.py` — présence et dernière exécution AIDE / Tripwire
- `bob/checks/clamav.py` — paquet ClamAV ; âge de la base freshclam ; âge du dernier scan
- `bob/checks/mac_policy.py` — AppArmor (profils chargés, enforce vs complain) / SELinux (enforcing vs permissive)
- `bob/checks/backup.py` — détection d'une solution de sauvegarde (restic, duplicati, borgbackup, rsync cron, timeshift)
- `bob/checks/disk.py` — santé SMART (smartctl) ; utilisation des partitions ; niveau d'usure NVMe
- `bob/checks/memory.py` — swap présent ; usure swap SSD ; réglage swappiness
- `bob/checks/ssl_certs.py` — scan d'expiration des certificats TLS/SSL (≤30 jours → WARN, ≤7 → ALERT)
- `bob/checks/systemd_timers.py` — timers système actifs ; timers manqués ; options de sécurité des unités timer
- `bob/checks/desktop_apps.py` — applications desktop installées (navigateurs, messagerie, etc.) sur profil serveur
- `bob/checks/samba.py` — durcissement Samba (map to guest, null passwords, min protocol, signing)
- `bob/checks/cron_audit.py` — scripts cron world-writable ; patterns pipe-to-shell ; format /etc/cron.d
- `bob/checks/ddns.py` — activité client DDNS (ddclient) ; reflété dans l'analyse d'exposition internet

#### Réseau
- `bob/sysinfo.py` — détection IP publique (3 fournisseurs : ipify → ifconfig.me → icanhazip) ; adresse IPv6 publique ; contexte réseau (serveur/LAN/CGNAT/VPN) ; GeoIP2 optionnel
- `bob/checks/network_context.py` — classification du type de réseau ; contexte d'exposition affiché par résultat
- `bob/checks/virtualization.py` — détection de virtualisation (KVM/VirtualBox/VMware/LXC/Docker)

### Mapping des benchmarks CIS

- `bob/cis_refs.json` — 133 entrées : `{"ref": "...", "code": "CIS:X.Y.Z"|null}`
  - 99 benchmarks CIS Ubuntu 22.04 (avec `code: "CIS:X.Y.Z"`)
  - 4 benchmarks CIS Docker (avec `code: "CIS Docker:X.Y"`)
  - 34 entrées bonnes pratiques (avec `code: null`)
- `bob/cis_refs.py` — `get_cis_ref(key)` / `get_cis_code(key)` — `_load()` avec `lru_cache(maxsize=1)`
- `bob/display.py` — `[CIS:X.Y.Z]` injecté en ligne dans la boîte de synthèse par résultat ; référence complète en mode `--verbose`
- `bob/explain.py` — mode TUI et clé directe `--explain CLÉ` ; appelle `get_cis_ref()` directement

### Sortie et formatage

- `bob/output.py` — sortie terminal colorée ; boîte de synthèse ; graphique en barres des scores par domaine ; panorama des services
- `bob/display.py` — rendu des lignes de résultats ; injection du code CIS ; couleur du score ; qualificateurs de portée (`[CRITIQUE • INTERNET]`)
- `bob/json_output.py` — `--format=json` / `--json`
- `bob/csv_output.py` — `--format=csv`
- `bob/markdown_output.py` — `--format=markdown`
- `bob/report_markdown.py` — rapport markdown complet
- `bob/html_output.py` — `--html` rapport HTML autonome

### Automatisation et planification

- `bob/cron.py` — assistant curses `--install-cron` ; TUI `--manage-cron` ; jobs nommés (`/etc/cron.d/bob-{nom}`) ; notification email si code de sortie > 0 ; détection des crons legacy
- `bob/manage_logs.py` — TUI `--manage-logs` ; gestion du répertoire de logs ; sparkline d'historique des scores
- `bob/webhook.py` — webhook JSON générique + Slack (détecté automatiquement) ; non-fatal ; timestamps UTC ; scores par domaine inclus
- `bob/history.py` — historique des scores ajouté dans `~/.config/bob/history.jsonl` ; sparkline `--history`
- `bob/domain_scores.py` — scores 0–10 sur 5 domaines ; graphique en barres ; inclus dans la sortie JSON/webhook
- `bob/watch.py` — boucle de polling `--watch[=N]` ; relance l'audit complet toutes les N secondes (60 par défaut)
- `bob/compare.py` — diff de baseline `--diff` ; affichage delta uniquement ; baseline dans `~/.config/bob/last_baseline.json`
- `bob/recurrence.py` — tracker de résultats récurrents ; comptage des apparitions consécutives par clé

### CLI et configuration

- `bob/cli.py` — analyseur d'arguments ; 7 sections ; options courtes (-V -v -d -j -C -p -e -D -w -o) ; `--check`/`--skip` ; `--format` ; `--output-dir` ; `--target` ; `--min-level`
- `bob/completion.py` — `--install-completion` ; script de complétion bash dans `/etc/bash_completion.d/bob`
- `bob/config.py` — store persistant clé=valeur dans `~/.config/bob/config.conf`
- `bob/ignore.py` — `--ignore`/`--show-ignored` ; `~/.config/bob/ignore.yml`
- `bob/fixes.py` — UI dry-run `--fix` ; exécution `--apply`

### Tests

4200 tests répartis dans 65 fichiers de tests.

| Fichier | Couverture |
|---------|-----------|
| `test_cis_refs.py` | `cis_refs.py` / `cis_refs.json` — 39 tests |
| `test_iptables_nftables.py` | CHECK 46 — iptables/nftables |
| `test_firewall.py` | Audit des règles UFW |
| `test_ssh.py` | Vérifications de configuration SSH |
| `test_hardening.py` | Sysctl durcissement noyau |
| `test_kernel_modules.py` | Audit des modules noyau |
| `test_services.py` | Registre de services + risque |
| `test_services_state.py` | Audit de l'état des services |
| `test_docker.py` · `test_docker_audit.py` | Vérifications Docker |
| `test_ports.py` · `test_exposure.py` | Exposition des ports |
| `test_scoring.py` · `test_domain_scores.py` | Moteur de scoring |
| `test_explain.py` · `test_display_explain_hint.py` | TUI --explain |
| `test_cli.py` · `test_exit_codes.py` | CLI + codes de sortie |
| `tests/helpers.py` | Utilitaires de test partagés |
| *(+ 50 fichiers de tests supplémentaires)* | Couverture complète de tous les modules |

---

© 2026 Cédric Clauzel
