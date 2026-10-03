<p align="center">
  <img src="https://raw.githubusercontent.com/Masbateno/bodyguard-of-bits/main/assets/logo_bob.png" alt="BOB — Bodyguard Of Bits" width="180">
</p>

*[Read in English](DOCTRINE.md)*

# BOB — Doctrine

Ceci est le *pourquoi*. [`CONVENTIONS.md`](CONVENTIONS_FR.md) est le *comment*
(couleurs, symboles, pattern Snapshot/check, localisation, SemVer) ; ce document est
l'ensemble des valeurs que ces conventions servent. Quand une décision de conception
n'est pas claire, elle se tranche ici, pas au goût. Deux parties : ce que BOB
**affirme** (la philosophie d'audit), et comment le projet est **construit et prouvé**
(la doctrine d'ingénierie).

---

## Partie I — Ce que BOB affirme

### 1. N'affirmer que le mesurable

BOB énonce des faits qu'il a lus, jamais des faits déduits du silence. « SSH autorise
le login root » n'est dit que lorsqu'un `sshd_config` parsé le dit — jamais parce
qu'un fichier était illisible et qu'un défaut compilé a été supposé. Ne rien cacher,
ne rien supposer, ne rien affirmer qu'on n'a pas mesuré. Tous les autres principes
ci-dessous découlent de celui-là.

### 2. inconnu ≠ propre

L'absence de lecture n'est pas un succès. Un vérificateur non installé, une config
illisible, une commande en timeout — chacun produit un *« non vérifié »* explicite,
jamais un verdict vert. BOB échoue **fermé** : quand il ne peut pas établir la
sûreté, il dit que la question reste ouverte. Fabriquer « propre » à partir de
« n'a pas pu regarder » est la pire chose qu'un auditeur puisse faire, car c'est la
seule erreur que l'opérateur ne peut pas voir.

### 3. Les trois questions de tri

Avant d'ajouter ou de conserver un check, un constat ou une déduction, répondre :

1. **Est-ce mesurable ?** BOB peut-il lire le fait directement, ou le déduit-il ?
2. **Est-ce actionnable ?** L'opérateur peut-il faire quelque chose de précis ?
3. **Est-ce honnête sur l'incertitude ?** Distingue-t-il « sûr », « pas sûr » et
   « n'a pas pu trancher » — ou effondre-t-il le troisième dans l'un des deux
   premiers ?

Un check qui échoue à l'une des trois est retravaillé ou abandonné.

### 4. Non-dogmatique, sensible au profil

BOB est un audit de durcissement, pas une machine à cocher des cases CIS. Un
contrôle juste pour un serveur exposé est faux pour un portable ou un conteneur,
donc les constats sont conditionnés au profil actif (`server` / `desktop` /
`workstation` / `container`) : le chiffrement intégral est WARN sur un desktop à
racine nue mais INFO sur un serveur dont le modèle de menace est une baie
verrouillée ; le verrouillage de compte PAM est WARN sur un serveur, INFO sur un
desktop où l'arbitrage verrouillage-vs-DoS diffère. BOB ne pénalise jamais une
configuration légitime juste parce qu'une checklist la nomme.

### 5. Signalé, pas scoré, quand le signal est ambigu

Un fait peut être réel et pourtant ambigu. Un binaire de paquet qui diffère de son
empreinte peut être une intrusion ou une recompilation locale ; un module noyau non
blacklisté est une opportunité de durcissement, pas une vulnérabilité. Ceux-là sont
émis en **INFO-only** : BOB les remonte et laisse le jugement à l'opérateur, plutôt
que d'inventer une déduction qu'il ne peut pas défendre. Les déductions sont
réservées aux faits à direction non ambiguë.

### 6. Ne jamais sur-affirmer, ne jamais sur-prescrire

Dire *plus* que ce que la mesure soutient est aussi malhonnête que de le cacher.
BOB n'annonce pas « aucun pare-feu » sur un hôte dont le ruleset nftables filtre, et
il n'exige pas un outil précis (`ufw`) quand `firewalld` ou un simple ruleset
netfilter ferait l'affaire. La remédiation qu'il propose est celle qui convient à la
distribution de *cet* hôte — une demi-remédiation (une commande Debian tendue à un
opérateur Fedora) n'est pas une remédiation.

### 7. Le score est une borne supérieure

Le score reflète ce que BOB a pu **voir**. Quand un check est aveuglé — un fichier
qu'il ne peut lire, une section qui échoue — le score ne monte pas pour combler le
trou ; l'incertitude est portée dans le résultat (`score_is_upper_bound`), et
aveugler un check peut *baisser* le score, jamais le monter. Un score élevé sur un
système à moitié lu est un mensonge que BOB refuse de dire.

### 8. Un verdict reproductible, indépendant du contexte de lancement

Auditer l'état *configuré* du système, pas l'état ambiant du shell dans lequel BOB a
tourné. Le PATH de root est lu depuis `login.defs` et sudoers, pas depuis l'`os.environ`
hérité ; la sortie des commandes est parsée sous `LC_ALL=C` pour qu'un verdict ne
dépende pas de la locale de l'opérateur. Le même hôte dans le même état donne le même
verdict, quel que soit qui l'a lancé et comment — un résultat qui change avec
l'environnement n'est pas une mesure de l'hôte.

### 9. BOB ne modifie pas le système dans le dos de l'opérateur

Pour tout ce qui est risqué ou difficile à annuler — piles PAM, `fstab`, chiffrement
de disque, un binaire set-id root modifiable par autrui — BOB **décrit** le correctif
et ne l'applique jamais. L'auto-application native (`--fix --apply`) est réservée aux
changements sûrs, réversibles et vérifiables, et elle ne prétend jamais à une
réussite qu'elle n'a pas confirmée. Un symptôme de compromission est à enquêter
avant de retourner un bit, pas un bit à retourner.

### 10. BOB ne téléphone pas à la maison

Un outil de sécurité qui exfiltre est une contradiction. BOB tourne **sans télémétrie
et sans trafic sortant** par défaut ; les seuls appels réseau qu'il fait sont une
résolution d'IP publique et, si l'opérateur en a configuré un, un webhook de résultat
— tous deux coupés par `--offline`, une garantie globale dure sur laquelle reposent
les sandboxes de build air-gap. Ce que BOB lit de l'hôte reste sur l'hôte, dans le
répertoire de rapports de l'opérateur.

### 11. Un check bruyant est pire que pas de check

Chaque faux positif dépense la confiance de l'opérateur, et la confiance est la
seule chose qui rend un audit utile. Un check qui crie au loup sur des
configurations légitimes est retiré ou resserré jusqu'à ce que son signal soit
propre — un constat agrégé plutôt que douze, le cas étroit non ambigu plutôt que le
cas large bruyant.

### 12. Un cadrage honnête

BOB audite une **posture de durcissement**, pas des menaces. Il ne modélise pas
d'adversaires, ne prédit pas d'attaques et ne score pas le « risque » au sens
actuariel. Il rapporte ce qui est exposé, ce qui est non vérifié et ce qui est
mal configuré face à une base de durcissement, et il le dit dans ces termes.

---

## Partie II — Comment le projet est construit et prouvé

### 13. Une garde doit tester ce qu'elle prétend, et une mutation doit le prouver

Chaque garantie de comportement est épinglée par un test, et chaque test est épinglé
par une **mutation** : une casse délibérée du code que le test surveille. Si la
mutation survit, le test ne teste pas ce qu'il prétend — un run vert ne prouve rien
à lui seul. Ajouter une garde, c'est ajouter sa mutation (`scripts/mutate.py`). Une
garde qui passe contre un chemin cassé-mais-masqué (un filtre éclipsé par un autre
filtre, un check qui contourne le vrai rendu) est réécrite jusqu'à ce que la
mutation morde.

### 14. Les sondes mentent ; le terrain est l'oracle

Un raisonnement sur ce qu'un système *devrait* rapporter n'est pas une preuve de ce
que BOB *rapporte*. Le comportement se prouve sur des machines réelles —
distributions réelles, systèmes d'init réels, pare-feu réels — par **paires de
polarité** (forger le mauvais état → le détecter → restaurer → confirmer qu'il
disparaît), outil par outil, entrées hostiles comprises (un FIFO là où un fichier de
config est attendu ne doit jamais faire hanger l'audit). Un banc local dans les
mêmes conditions vaut l'instance ; un test unitaire synthétique, non.

### 15. Mesurer avant de corriger, corriger étroit, rejouer

Un `exit 0` n'est pas la preuve d'un correctif. Détecter large (trouver toutes les
instances d'une classe), réparer étroit (ne changer que ce que la preuve exige),
puis rejouer contre la condition qui l'a révélé — en aller-retour conteneur quand
c'est possible : appliquer, ré-auditer, voir le constat disparaître. Un balayage
statique qui liste 180 candidats et zéro priorité vaut moins qu'un banc hostile qui
trouve les deux qui comptent.

### 16. Gain faible × risque non nul = STOP

Un refactor qui ne change aucun verdict, ne ferme aucun trou réel et porte un risque
quelconque n'est pas fait. Le conservatisme est le défaut pour un outil dont toute
la valeur est que sa sortie peut être crue. Quand le bénéfice d'un changement est
faible et que son rayon d'impact ne l'est pas, il attend une raison.

### 17. Une commande bornée, et un timeout qui tue le groupe

Chaque sous-processus tourne sous un timeout fini. Un vérificateur délibérément lent
(`rpm -Va`) tourne dans son propre groupe de processus pour qu'au dépassement du
délai, le **groupe entier** soit tué — pas seulement le parent, qui laisserait du
travail orphelin derrière lui. BOB ne fait jamais hanger le cron d'un opérateur.

### 18. Dire ce qui a changé, honnêtement

Un changelog n'affirme jamais « aucun changement de comportement » à plat quand une
sortie bouge. Il nomme les invariants qui ont tenu (formule de score, schéma JSON,
ordre des colonnes CSV, règles de détection) *et* les sorties qui ont changé, dans
les termes de l'opérateur. Un changement BREAKING est étiqueté BREAKING même sur un
diff de forme patch.

### 19. Juger l'avis ; ne suivre aucun oracle

Un avis externe — d'une autre IA, d'un relecteur, d'un benchmark — est pesé sur le
fond, point par point, accepté ou rejeté avec une raison énoncée. Rien n'est adopté
à cause de sa source. Une checklist qui nomme un contrôle que BOB livre déjà, ou qui
recommande un check qui serait du bruit, est déclinée et le raisonnement conservé.

### 20. La documentation est auditée comme le code

Chaque affirmation chiffrable de la doc (compteurs de clés, de sections, totaux
locale) est épinglée par une garde, car un nombre gelé est un mensonge qui attend de
se produire. La justesse documentaire suit la même règle que l'audit lui-même
(principe 1) : n'affirmer que le mesurable, et laisser une machine attraper la
dérive.

### 21. Les références viennent d'une autorité, pas de la mémoire

Un numéro CIS ou de benchmark que BOB imprime est généré depuis sa source amont
(ComplianceAsCode) par le nom de la règle, jamais tapé à la main de mémoire. Citer un
standard est en soi une affirmation, et le principe 1 s'y applique : la référence doit
remonter à quelque chose de vérifiable, pas à un nombre d'apparence plausible.

### 22. La dernière étape avant une étape irréversible est un arrêt

Publier sur PyPI est irréversible. Avant toute étape de release irréversible, le
mainteneur de BOB s'arrête, vérifie, et n'agit que sur un feu vert explicite. La
release est prouvée (suite complète verte, chaque mutation tuée, `ruff` propre,
version cohérente partout) *avant* le tag, pas après.

---

© 2026 Cédric Clauzel
