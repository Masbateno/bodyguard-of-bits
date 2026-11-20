*[Read in English](FIX_JOURNAL.md)*

# BOB — le journal de `--fix --apply`, et comment une falsification se voit

`--fix --apply` modifie le système. Depuis la 0.40.0, chaque commande qu'il
lance laisse une entrée dans un journal tenu pour l'hôte — qui l'a lancée, à
quel constat elle répondait, la commande exacte, ce qu'il en est advenu — et
chacun peut ajouter une note à une entrée, jamais en modifier une.

Un journal ne vaut que la confiance qu'on peut lui accorder : ce document dit
donc exactement sur quoi repose cette confiance, et le montre. En bref :

> **BOB ne peut pas rendre ce journal infalsifiable.** Il vit sur la machine
> qu'il décrit, et root peut y réécrire n'importe quel fichier. Ce que fait
> BOB, c'est rendre une falsification **visible**, et vous en donner **la
> preuve** : la ligne modifiée, et ce que le journal système a enregistré
> quand cette ligne a été écrite.

Tout ce qui suit a été mesuré sur une vraie machine (Linux Mint 22.3,
systemd 255, ext4) le 20 novembre 2026, avec deux opérateurs ; les sorties sont
celles de BOB, raccourcies seulement là où une empreinte dépasse la page.

---

## 1. Ce qui est enregistré

Une entrée par commande que `--fix --apply` **lance**, quel qu'en soit le
résultat :

| Champ | Ce qu'il contient |
|---|---|
| quand | la date et l'heure où la commande a commencé, et l'heure où elle s'est terminée |
| qui | le compte que nomme le **login uid** du noyau — il survit à `sudo` — et la déclaration `SUDO_USER`/`DOAS_USER` à côté, la même mesure que pour les notes d'un rapport. Dans la ligne brute, `by={"login":"bobop2","sudo":"bobop2","uid":0}` se lit : connecté comme `bobop2`, déclarant `bobop2` par `sudo`, et BOB lui-même tournant avec l'uid effectif 0 — l'`uid` est celui du processus, jamais celui de l'opérateur |
| constat | le constat auquel la commande répondait (sa clé et son message) |
| commande | la commande exacte ; pour un correctif que BOB exécute par son propre code (sysctl), l'action exécutée aussi |
| résultat | appliquée · en échec · délai dépassé · lancée sans que son effet ait pu être confirmé — avec le code de sortie, la durée et la sortie d'erreur (bornée) |
| notes | ajoutées après coup, datées, leur auteur enregistré ; jamais modifiées, jamais retirées |

Une commande que l'opérateur refuse, ou que BOB refuse de lancer (opérateurs
du shell), n'est pas lancée et ne laisse pas d'entrée.

Chaque entrée s'écrit en **deux lignes** : l'une avant que la commande démarre,
l'autre avec son résultat. Deux écritures, pas la promesse de deux lignes :
quand la seconde manque, l'entrée se lit *aucun résultat inscrit*, pour l'une de
deux raisons que le journal ne distingue pas — BOB s'est arrêté pendant la
commande (le correctif de pare-feu qui coupe la session SSH où BOB tourne, une
coupure de courant), ou son résultat n'a pas pu être écrit, ce que BOB a dit à
l'écran sur le moment. Dans les deux cas la commande reste visible, et ce
qu'elle a fait n'est pas affirmé.

**Aucune commande ne tourne sans son entrée.** Avant la première commande, BOB
ouvre le journal en écriture ; s'il ne le peut pas (un lien à son nom, un
journal ou un dossier qui n'appartient pas à root), il s'arrête là et ne lance
rien. Une commande dont la première ligne ne peut pas être écrite (un disque
plein) n'est pas lancée, et BOB dit pourquoi.

## 2. Où il vit, qui l'écrit, qui le lit

| | |
|---|---|
| Fichier | `/var/log/bob/fixes.journal` — un pour l'hôte, quel que soit celui qui a lancé BOB |
| Propriétaire | `root:adm`, mode `0640` ; le dossier `root:adm`, `0750` |
| Écrit par | root seulement — le seul compte qui lance `--fix --apply` ou ajoute une note |
| Lu par | root, et les membres de `adm` (le groupe qui lit les journaux du système) |
| Ouvert | sans suivre de lien, sous verrou ; un journal ou un dossier qui n'appartient pas à root est dit ne pas être celui de BOB, et rien n'y est écrit |

Où le lire : `sudo bob --manage-logs`, second choix de l'écran d'accueil
(*Journal des correctifs*), ou `bob --fix-journal` en texte.

## 3. Comment une falsification se voit — quatre mesures

Aucune ne suffit seule ; chacune couvre ce que les autres ne peuvent pas.

### 3.1 La chaîne

Chaque ligne porte l'empreinte (SHA-256) de la ligne précédente. Une ligne
modifiée, retirée au milieu ou déplacée casse la chaîne à cet endroit.

*Limite :* les empreintes ne sont pas une signature. Qui réécrit le fichier peut
recalculer toutes les empreintes après la ligne qu'il a modifiée, et la chaîne
seule ne montre alors plus rien. Des lignes coupées à la fin, ou le fichier
supprimé, ne laissent aucune trace dans le fichier lui-même.

### 3.2 Le témoin dans le journal système

Chaque ligne, au moment où elle est écrite, est aussi envoyée au journal
système (`/dev/log`, journald ou syslog) sous le nom `bob-fix`, avec **deux
empreintes** : celle de la ligne entière, et celle de ce qu'elle dit sans son
lien à la ligne précédente. BOB les relit (`journalctl
SYSLOG_IDENTIFIER=bob-fix`) et confronte le journal à elles :

* une ligne qui **diffère** de ce que son témoin a enregistré — **falsifiée**,
  chaîne recalculée ou non ;
* une ligne qui dit ce qu'elle disait mais dont le lien a été recalculé après
  une modification plus haut — **rechaînée** : la chaîne a été réécrite ;
* un témoin **sans ligne** dans le journal — des lignes **coupées** à la fin,
  ou le journal supprimé ;
* une ligne, **deux témoins qui se contredisent** — un témoin forgé à côté du
  vrai ;
* une ligne sans témoin alors que le journal système couvre sa date — **non
  démontrée** : rien ne prouve une falsification, rien ne prouve la ligne ;
* une ligne plus ancienne que tout ce que garde le journal système — son témoin
  est parti avec la rotation du journal : **dit, jamais appelé falsification**.

Seul compte ce que **root** a envoyé. journald enregistre l'uid de l'expéditeur
(`_UID`) d'après les identifiants de la socket, pas d'après ce que dit
l'expéditeur : un compte ordinaire peut écrire `logger -t bob-fix "…"`, mais sa
ligne porte son propre uid et BOB la laisse de côté (mesuré, §5.3).

Ce `_UID` dit *qui* a envoyé une ligne — un compte qui a les privilèges de root —
pas *quel programme* l'a écrite : n'importe quel processus qui tourne en root
peut envoyer une ligne sous le nom `bob-fix`. Une telle ligne, sans ligne du
journal de même identifiant, se montre comme une ligne coupée ; à côté d'une
vraie, comme deux témoins qui se contredisent — dans les deux cas **falsifié**,
et c'est exact : quelque chose qui a les droits de root a écrit au nom de BOB.

*Limite :* root peut réécrire aussi le journal système — sauf s'il est scellé
(§3.4) ou copié sur une autre machine (§6).

### 3.3 L'attribut d'ajout seul

BOB pose `chattr +a` sur le journal. Le noyau refuse alors de le réécrire, de
le tronquer ou de le supprimer — root compris — tant que l'attribut n'est pas
retiré (mesuré, §5.1). Le retirer est un geste délibéré, et chaque ligne
enregistre si l'attribut était posé quand elle a été écrite : trouvé absent
depuis, BOB le dit.

*Limite :* root peut le retirer, réécrire, puis le reposer. Il relève la barre et
laisse une marque ; c'est le témoin qui prouve.
Là où le système de fichiers n'a pas cet attribut (tmpfs, overlayfs) ou que
BOB n'a pas le droit de le poser (dans un conteneur), l'écran dit
*indisponible*.

### 3.4 Le scellement propre à journald

journald sait sceller ses propres fichiers (Forward Secure Sealing) : configuré
avec `journalctl --setup-keys`, il donne une clé de vérification à garder
**hors de la machine** ; `journalctl --verify --verify-key=…` montre alors un
journal système réécrit après coup. BOB dit si le scellement est configuré ; il
ne le configure jamais à votre place. Avec lui, le témoin du §3.2 ne peut plus
être réécrit sans que cela se voie.

## 4. Lire le verdict

Le verdict vient en tête de l'écran et du texte, dans sa couleur :

| Verdict | Sens | Code de sortie de `bob --fix-journal` |
|---|---|---|
| ✔ **INTACT** | la chaîne tient et chaque ligne que BOB a pu vérifier correspond à son témoin | 0 |
| ⚠ **NON DÉMONTRÉ** | rien ne montre de falsification, mais tout n'a pas pu être vérifié : une ligne sans témoin, le journal système illisible pour ce compte, l'attribut d'ajout seul retiré | 4 |
| ✖ **FALSIFIÉ** | une falsification est montrée : chaîne cassée, ligne différente de son témoin, chaîne recalculée, lignes coupées, témoin forgé, journal qui n'appartient pas à root | 2 |

Sous le verdict, chaque constat est listé avec le nombre de lignes qu'il
concerne ; sous chaque entrée que le témoin contredit, les lignes que le journal
système a enregistrées quand elle a été écrite — la preuve, prête à être copiée
dans un ticket. Dans `--manage-logs`, un jour qui contient une entrée falsifiée
est marqué, l'entrée est marquée, et `r` liste les lignes coupées.

Le code de sortie en fait un contrôle de supervision :

```bash
bob --fix-journal >/dev/null; case $? in 0) ;; 2) echo "journal des correctifs FALSIFIÉ";; *) echo "journal des correctifs non démontré";; esac
```

## 5. Démonstration

Mesurée sur la machine de test le 20 novembre 2026. Deux opérateurs ont
appliqué chacun un correctif : `root` connecté directement (login uid 0), et
`bobop2` par `sudo` (login uid 1001). Chacun a ajouté une note à la première
entrée par `sudo bob --manage-logs`. Le journal se lisait alors ainsi :

```text
✔ INTACT — la chaîne tient et 6 ligne(s) correspondent à leur témoin dans le journal système
  Témoin : le journal système (journald), relu
  Scellement de journald (FSS) : non configuré — root pourrait réécrire aussi le journal système (journalctl --setup-keys)
  Attribut d'ajout seul (chattr +a) : posé — le noyau refuse de réécrire le journal, root compris

vendredi 20 novembre 2026 — 2 commande(s) : 2 appliquée(s), 0 en échec, 0 autre(s)
  21:47:25  ✔ appliquée    root             sudo sysctl -w net.ipv4.conf.all.accept_redirects=0 …
      20/11/2026 21:49  root : verifie par root : sysctl relu
      20/11/2026 21:49  bobop2 : vu par bobop2
  21:48:22  ✔ appliquée    bobop2           sudo sysctl -w net.ipv6.conf.all.accept_redirects=0 …
[code de sortie : 0]
```

### 5.1 Réécrire le journal, en root

Avec l'attribut posé, le noyau refuse — root compris :

```text
$ sed -i s/bobop2/root/ /var/log/bob/fixes.journal
sed: impossible de renommer /var/log/bob/sedWPWjzp: Opération non permise
$ truncate -s 0 /var/log/bob/fixes.journal
truncate: impossible d'ouvrir '/var/log/bob/fixes.journal' en écriture: Opération non permise
$ rm -f /var/log/bob/fixes.journal
rm: impossible de supprimer '/var/log/bob/fixes.journal': Opération non permise
```

### 5.2 Retirer l'attribut, attribuer à root la commande de bobop2, recalculer la chaîne

La tentative de cacher qui a fait quoi : `chattr -a`, puis chaque ligne écrite
par `bobop2` réécrite au nom de `root` — sa commande, son résultat, sa note —
et toutes les empreintes recalculées pour que la chaîne tienne. La chaîne seule
ne montre rien ; le témoin, si :

```text
✖ FALSIFIÉ — ce journal a été modifié hors de BOB (preuves ci-dessous)
  3 ligne(s) diffèrent de leur témoin : ce qu'elles disent a été modifié
  1 ligne(s) disent ce qu'elles disaient mais ont été rechaînées après une ligne modifiée : la chaîne a été recalculée
  l'attribut d'ajout seul a été retiré depuis la dernière entrée (chattr -a) : un geste délibéré, que le contenu a pu suivre
  …
vendredi 20 novembre 2026 — 2 commande(s) : 2 appliquée(s), 0 en échec, 0 autre(s)   [✖ falsifié]
  21:47:25  ✔ appliquée    root             sudo sysctl -w net.ipv4… [✖ modifiée]
    Ce que le journal système a enregistré quand ses lignes ont été écrites :
    20/11/2026 21:49  note id=51e459a65d78 sha256=037eee… of=04322d19283d by={"login":"root","uid":0}
    20/11/2026 21:49  note id=75a48b385f90 sha256=d024c9… of=04322d19283d by={"login":"bobop2","sudo":"bobop2","uid":0}
      20/11/2026 21:49  root : verifie par root : sysctl relu
      20/11/2026 21:49  root : vu par bobop2
  21:48:22  ✔ appliquée    root             sudo sysctl -w net.ipv6… [✖ modifiée]
    Ce que le journal système a enregistré quand ses lignes ont été écrites :
    20/11/2026 21:48  run id=eb87e0cef2eb sha256=2954bb… by={"login":"bobop2","sudo":"bobop2","uid":0} …
    20/11/2026 21:48  result id=7feacb20c2b0 sha256=845953… of=eb87e0cef2eb status=ok rc=0
[code de sortie : 2]
```

Le journal dit désormais `root` ; le journal système, écrit au moment où la
commande a tourné, dit `bobop2` — côte à côte. La première note (celle de
`root`) est listée parce qu'elle a été rechaînée après la note forgée.

### 5.3 Un témoin forgé par un compte ordinaire

`bobop2`, sans `sudo`, envoie une ligne au nom du témoin, avec l'identifiant
d'une des entrées :

```text
$ logger -t bob-fix 'run id=eb87e0cef2eb sha256=0000… body=0000… by={} finding=x cmd=x'
$ journalctl -t bob-fix -o verbose -n 1
    _UID=1001
    MESSAGE=run id=eb87e0cef2eb sha256=000000000000000000000000000000000000000000000000000
```

journald a enregistré `_UID=1001`. BOB laisse la ligne de côté : le verdict
reste **✔ INTACT**, code de sortie 0.

### 5.4 Couper la fin du journal

Les deux notes retirées, la chaîne recalculée sur ce qui reste :

```text
✖ FALSIFIÉ — ce journal a été modifié hors de BOB (preuves ci-dessous)
  2 ligne(s) diffèrent de leur témoin : ce qu'elles disent a été modifié
  2 ligne(s) du journal système manquent au journal : coupées à sa fin, ou journal supprimé (preuves ci-dessous)
  …
Lignes que le journal système garde et que le journal n'a plus (2) :
  20/11/2026 21:49  note id=51e459a65d78 sha256=037eee… of=04322d19283d by={"login":"root","uid":0}
  20/11/2026 21:49  note id=75a48b385f90 sha256=d024c9… of=04322d19283d by={"login":"bobop2","sudo":"bobop2","uid":0}
[code de sortie : 2]
```

### 5.5 Supprimer le journal

```text
✖ FALSIFIÉ — ce journal a été modifié hors de BOB (preuves ci-dessous)
  6 ligne(s) du journal système manquent au journal : coupées à sa fin, ou journal supprimé (preuves ci-dessous)
  …
Lignes que le journal système garde et que le journal n'a plus (6) :
  20/11/2026 21:47  run id=04322d19283d … by={"login":"root","uid":0} finding=hardening.redirects_enabled …
  20/11/2026 21:47  result id=6fabb6389019 … of=04322d19283d status=ok rc=0
  20/11/2026 21:48  run id=eb87e0cef2eb … by={"login":"bobop2","sudo":"bobop2","uid":0} …
  …
[code de sortie : 2]
```

Ce qui a été supprimé se lit encore, dans le journal système.

### 5.6 Un lecteur sans le droit

`bobop2` sans `sudo`, hors du groupe `adm` :

```text
⚠ Le journal /var/log/bob/fixes.journal n'a pas pu être lu : permission refusée — le lire en root ou en tant que membre du groupe adm
[code de sortie : 4]
```

Un membre de `adm` lit le journal et son témoin sans `sudo`, et obtient le même
verdict que root.

### 5.7 Et le journal remis à l'identique

Recopié octet pour octet depuis l'état d'avant le §5.1, le journal se lit de
nouveau **✔ INTACT** : ce dont BOB répond, c'est de ce que dit le journal, ligne
par ligne, face à ce qui a été enregistré quand il a été écrit — et il redit
exactement cela.

### 5.8 Le journal système parti en rotation

`journalctl --rotate`, puis `journalctl --vacuum-time=1s` : les anciens
fichiers du journal système partent, et avec eux les huit lignes témoins. Ce
n'est pas une falsification — c'est dit pour ce que c'est :

```text
✔ Chaîne intacte — aucune ligne n'a pu être confrontée à son témoin (parti avec la rotation du journal système, ou illisible) : seule la chaîne répond du journal
  6 ligne(s) sont plus anciennes que tout ce que garde le journal système : leur témoin est parti avec sa rotation
[code de sortie : 0]
```

La première formulation, mesurée ici avant la publication, disait *INTACT — …
0 ligne(s) correspondent à leur témoin* : exact, et trompeur. Elle dit
désormais que seule la chaîne répond de ces lignes.

### 5.9 Le scellement configuré

Avant `journalctl --setup-keys`, BOB disait *non configuré* ; après (et une
rotation, pour que journald commence à sceller), *configuré*, et
`journalctl --verify` passe. BOB cherche la clé de scellement que journald garde
à côté de ses fichiers ; il ne détient pas la clé de vérification — celle-là
reste hors de la machine, chez vous.

### La rejouer

Sur une **machine virtuelle jetable**, jamais sur une machine dont on veut
garder le journal : les lignes du témoin restent dans le journal système, et
une fois le journal falsifié ou supprimé, BOB les signalera comme manquantes
jusqu'à ce que journald les fasse tourner — c'est tout l'intérêt.

```bash
sudo bob --fix --apply                     # appliquer un ou deux correctifs (répondre y)
bob --fix-journal                          # ✔ INTACT (en root ou membre de adm)
sudo sed -i 's/"login":"[a-z]*"/"login":"x"/' /var/log/bob/fixes.journal   # refusé : chattr +a
sudo chattr -a /var/log/bob/fixes.journal
sudo sed -i 's/"login":"[a-z]*"/"login":"x"/' /var/log/bob/fixes.journal   # modifié, chaîne cassée
bob --fix-journal; echo $?                 # ✖ FALSIFIÉ, 2 — et les lignes enregistrées
sudo rm /var/log/bob/fixes.journal
bob --fix-journal; echo $?                 # ✖ FALSIFIÉ, 2 — chaque ligne, depuis le journal système
```

## 6. Ce qui reste hors de portée

Dit simplement, parce que c'est là que s'arrête la confiance :

* **root qui réécrit les deux**, le journal et le journal système, de façon
  cohérente — ou qui supprime les deux — sur un hôte où le journal système
  n'est ni scellé (§3.4) ni copié sur une autre machine. La seule vraie
  parade contre root est une copie que root ne détient pas : transférer le
  journal système vers un serveur de journaux (rsyslog,
  `systemd-journal-upload` de journald), et le sceller.
* **les lignes plus anciennes que la rétention du journal système** : leur
  témoin est parti avec la rotation de journald ; seule la chaîne répond
  d'elles, et BOB le dit.
* **un journal système gardé en mémoire seulement** (`/run/log/journal`,
  `Storage=volatile`) : le témoin se perd au redémarrage ; BOB le dit.
* **un hôte sans journald** (syslog de busybox sur Alpine) : le témoin est écrit
  mais ne peut pas y être relu ; BOB le dit.
* **un journal remis à l'identique** (§5.7) ne laisse rien voir — et il n'y a
  alors rien de caché.

Les empreintes prouvent que le journal a changé, pas qui l'a changé. Une chaîne
ou un témoin sont des éléments à présenter à quelqu'un, pas une signature.

---

© 2026 Cédric Clauzel
