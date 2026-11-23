*[Read in English](CONVENTIONS.md)*

# BOB — Conventions

Comment ce projet fait les choses, en un seul endroit : ce que veut dire une
couleur, ce que veut dire un symbole, et les motifs de code qu'un check doit
suivre. Pour le *pourquoi* qu'ils servent — ce que BOB affirme et comment c'est
prouvé — voir [`DOCTRINE.md`](DOCTRINE_FR.md).

Tout ce qui suit était vrai à l'écriture, et l'essentiel est désormais vérifié.
La distinction compte : ce projet a deux fois trouvé une convention vivant dans
trois modules qui se trouvaient d'accord — la charte curses a partagé son cyan
entre la ligne de curseur et le bandeau pendant neuf versions, faute de quoi que
ce soit qui les compare. Une règle vérifiable mécaniquement porte le nom de sa
garde ; une règle qui ne l'est pas le dit.

---

## 1. Couleur — sortie terminal

Quinze séquences ANSI sont définies dans `bob/output.py` (`_Colours`) : `reset`
et quatorze couleurs et graisses. La table donne le sens de celles qui en
portent un ; elle fait autorité, et aucun module ne fabrique lui-même une
séquence d'échappement.

| Couleur | Signifie |
|---|---|
| vert | un constat OK, un score qui monte |
| jaune | un avertissement, un score qui baisse, une cible invérifiable |
| rouge | une alerte |
| cyan | une information, un marqueur de récurrence |
| `dim` | détail secondaire : codes CIS, indications, la prose autour d'une commande |
| **`violet_bold`** | **de la matière à reproduire à l'identique** — une commande à lancer, ou une directive à écrire |
| `orange` | un en-tête `[ profil ]` dans `--explain` |
| `blue_bold` | la bordure d'une boîte de synthèse |
| `bold` | un titre de boîte, un en-tête de section |
| `yellow_bold` | un titre dans l'écran des correctifs |

**Le violet est celui qui porte une information, pas une humeur.** Il marque ce
qui doit être reproduit à l'identique — *ne paraphrase pas, recopie* — que ce
soit une commande à lancer ou une ligne à écrire dans un fichier de
configuration. Un drapeau *cité* dans une phrase n'est ni l'un ni l'autre :
« l'exécution a été restreinte par `--check` / `--skip` » décrit ce qui s'est
passé et n'offre rien à recopier. Colorer chaque `--drapeau` de la locale ferait
cesser au violet de signaler quoi que ce soit.

**Pourquoi ce n'est pas « une commande exécutable ».** C'était le premier
libellé, et `server signing = mandatory` dans un bloc `HOW TO FIX` n'est pas une
commande. Restreindre le violet aux commandes n'est ni fiable ni utile. Pas
fiable : 37 de ces lignes sont `sudo nano <fichier>  →  <directive>` — une
commande et une directive sur une ligne, qu'aucune couleur par ligne ne peut
séparer — et classer le reste a demandé une regex de soixante binaires laissant
encore 16 % non triés. Une règle qui exige une telle liste est une heuristique,
et elle dérive au premier check utilisant un binaire que personne n'a listé. Pas
utile : du point de vue de l'opérateur, les deux disent la même chose, et la
prose au-dessus indique déjà s'il faut lancer ou écrire — *« Edit
/etc/samba/smb.conf → In the `[global]` section set: »*.

Un coût assumé : quelques lignes associent une commande à sa sortie attendue
(`ls -la <chemin>  →  -rw------- owner owner`), donc la sortie attendue est
violette elle aussi. Cela reste de la matière à comparer littéralement.

**Une mention n'est pas l'endroit canonique où recopier.** *« Run `sudo
fwupdmgr update` to apply pending firmware updates »* est une phrase, et la même
commande se trouve une ligne plus loin comme `cmd` du constat, où elle est
violette. Colorer les deux rendrait la couleur ambiante. Le violet marque le
seul endroit où recopier — le début d'une ligne, ou ce qui suit le `→` / `ℹ` /
`?` qui l'introduit.

Une commande insérée dans une phrase passe par `output.command()`, et la phrase
elle-même est un gabarit de locale avec un `{cmd}` — jamais une chaîne où la
commande est fondue, qu'on ne peut colorer sans colorer la prose.

**Demander si la couleur est active a une seule réponse.** `_c` contient des
chaînes vides quand la couleur est éteinte, donc `f"{_c.red}…{_c.reset}"` est
déjà correct dans les deux états. Ne consultez pas `_no_color` — c'était la
seconde façon de poser la même question, et `print_help` l'utilisait quand tout
le reste utilisait la première.

*Gardé :* toute couleur déclarée est consommée · une indication de commande est
un gabarit · `output.command` peint en violet · `print_dim` rétablit son gris
après une couleur qu'il contient.

---

## 2. Couleur — écrans curses

Dix-sept paires, définies une seule fois dans `bob/tui/_palette.py`. **N'appelez pas
`init_pair` hors de ce module** — une garde le rejette, et elle existe parce que
trois écrans ont un jour initialisé la même charte chacun de leur côté en étant
d'accord, ce qui est ainsi que la ligne de curseur et le bandeau ont partagé un
fond sans que personne le voie.

| Paire | Rôle |
|---|---|
| `SELECTION` | la ligne sous le curseur — noir sur orange |
| `ACCENT` | en-têtes de groupe, invites |
| `NORMAL` | lignes ordinaires |
| `NOTICE` | par écran : rouge pour une liste d'avertissements, cyan pour l'en-tête de détail d'`--explain` |
| `BANNER` | le bandeau de titre — blanc sur cyan |
| `PROFILE` | un en-tête `[ profil ]` |
| `FOOTER` | le bandeau de touches du bas — blanc sur orange |
| `CONTEXT` | la ligne au-dessus, pour les invites et messages — blanc sur noir |
| `VERBATIM` | de la matière à reproduire à l'identique — violet, comme en sortie texte |
| `CONTEXT_PROMPT` | la ligne de contexte portant une invite ou une question — jaune sur noir |
| `CONTEXT_OK` | la ligne de contexte disant qu'une action a pris effet (`✔`) — vert sur noir |
| `CONTEXT_ERROR` | la ligne de contexte disant qu'une action a été refusée ou a échoué (`✖`) — rouge sur noir |
| `CONTEXT_INFO` | la ligne de contexte qui informe seulement (`ℹ`, une action annulée) — cyan sur noir |
| `KEYCAP` | la pastille d'une touche dans le bandeau du bas — noir sur blanc (v0.40.0) |
| `ACCOUNT` | un nom de compte, dans tous les assistants — cyan, gras (v0.43.0) |
| `POSITIVE` | le terme d'un journal pour ce qui ajoute ou active — vert, gras (v0.43.0) |
| `NEGATIVE` | le terme d'un journal pour ce qui retire, désactive ou alerte — rouge, gras (v0.43.0) |

**La ligne de contexte dit ce que signifie un message** (v0.39.0, décidé avec
l'utilisateur). Sa couleur est celle de la sortie texte pour le même sens — vert
réussi, rouge refusé, cyan information — et une invite prend le jaune
d'`ACCENT`, la couleur curses des invites. Pas de jaune pour un refus : en curses
le jaune est une invite, et un refus en jaune se lirait comme une question. Un
message porte son sens dans son premier symbole, construit avec
`_chrome.done()` / `refused()` / `info()`, et la barre du bas en déduit la
couleur ; une invite est déclarée (`tone=_chrome.PROMPT`). **Rien ne s'écrit sur
la ligne du bandeau des touches** que le bandeau : un message ou une
confirmation va sur la ligne de contexte au-dessus. Trouvé en le faisant : le
carnet d'adresses de `--manage-cron`, sa liste d'adresses et sa liste de tâches,
et deux confirmations de `--manage-logs`, remplaçaient encore le bandeau.
*Gardé :* la couleur de chaque symbole · la paire de chaque couleur · chaque
message construit avec son symbole · aucune écriture sur la ligne du bandeau ·
les invites dans la couleur des invites.

**Chaque touche a sa pastille** (v0.40.0, décidé avec l'utilisateur, 20 novembre
2026 : sur la ligne orange uniforme, on distinguait mal les touches). Dans le
bandeau du bas, chaque touche — `⏎`, `Échap`, `d`, `1-4` — est dessinée noir sur
blanc (`KEYCAP`), avec l'espace de chaque côté ; son libellé reste blanc sur
orange. Les trois touches de navigation (`↑↓ jk`, `PgUp/PgDn`, `g/G`) ont chacune
leur pastille, serrée sur la touche, une espace orange entre elles : une seule
pastille sur tout le groupe se lisait comme un bloc blanc (l'utilisateur). Sans couleurs, la pastille est en
vidéo normale sur la vidéo inversée du bandeau. Le texte du bandeau est celui
qu'il a toujours été : aucune largeur ne bouge, aucune ligne ne se replie
autrement (`_keys.footer_layout` donne à chaque ligne ses pastilles). *Gardé :*
les pastilles couvrent chaque touche et rien d'autre · elles sont dessinées dans
leur couleur, et à part sans couleurs · le texte est inchangé sur chaque écran.

**Toute confirmation se demande d'une seule façon** (v0.39.0, décidé avec
l'utilisateur, 19 novembre 2026). Une action qui supprime, écrase, retire, purge
ou déplace quelque chose demande d'abord, sur la ligne de contexte, dans le
jaune des invites, le bandeau des touches laissé dessous : la question, puis
`Appuyez sur y pour confirmer, sur toute autre touche pour annuler.` Elle se
construit avec `_chrome.confirm_text()` ou se pose avec `_chrome.ask_confirm()` ;
une question n'écrit jamais sa propre consigne, qui vit dans une seule clé,
`tui.confirm_suffix`. `y` confirme ; toute autre touche, Échap compris, annule,
et une annulation le dit (`ℹ`). Ce sur quoi porte l'action est lu avant toute
autre question : un numéro sans entrée est refusé tout de suite, pas après la
saisie d'un motif. En mode texte (sans terminal), la même question finit par
`[y/N]`, Entrée valant non. Appliquer un nouveau planning dans `--manage-cron`,
qui ne supprime rien, garde `y` ou Entrée. Trouvé en le faisant : le carnet
d'adresses de `--manage-cron` supprimait sans rien demander, sa liste de tâches
demandait sans dire comment répondre, `--install-cron` attendait `y` ou Échap
avant d'écraser une tâche et ignorait toute autre touche, et la liste des
rapports en mode texte supprimait par numéro sans rien demander. *Gardé :* la
formulation · `y` confirme, toute autre touche annule · aucune question ne porte
sa propre consigne · chaque assistant demande par la confirmation commune · le
carnet d'adresses et la liste en mode texte demandent.

**Un écran accepte exactement les touches qu'il annonce** (v0.39.0, décidé avec
l'utilisateur, 19 novembre 2026). Le bandeau liste toutes les touches auxquelles
l'écran répond, et l'écran ne répond à aucune autre : une touche qu'il n'annonce
pas ne fait rien — ni déplacement, ni marque, ni redessin, ni sortie. La 0.16.3 a
fait marcher chaque touche annoncée ; c'est l'autre moitié. Une touche qui n'agit
que dans certains états n'est annoncée que dans ces états : `u` dès que quelque
chose est marqué ; `n` sur un rapport qui a des notes ; Entrée et `m` quittent le
bandeau de la liste des tâches tant que des tâches sont marquées. Un menu numéroté
annonce ses chiffres avec son propre intervalle (`1-4 par numéro`,
`_keys.pick(n)`). Un champ de texte dessine son propre bandeau — Entrée, Échap, et
Tab là où il complète un chemin ; la frappe et Retour arrière sont le champ
lui-même. Le bandeau d'une confirmation est `y`, sa question disant que toute
autre touche annule. La casse ne fait pas une autre touche : `Q` est `q`. Ce
qu'un écran annonce et ce qu'il accepte viennent d'un seul tuple d'actions
(`_keys.accepted()`). Trouvé en le faisant : la confirmation du planning prenait
Entrée pour oui et toute autre touche pour non, son bandeau disant `y` et Échap ;
l'éditeur de tâche annonçait Entrée et Échap et prenait les flèches, `jk`,
PgUp/PgDn, `g`/`G` et deux chiffres (un chiffre n'agissait que si le curseur était
déjà sur son entrée) ; chaque menu numéroté prenait ses chiffres sans les
annoncer ; le carnet d'adresses prenait `u` sans l'annoncer ; un champ de texte de
`--manage-logs` et les confirmations gardaient le bandeau de l'écran, dont aucune
touche ne faisait alors ce qu'elle disait. *Gardé :* en boîte noire, écran par
écran — le bandeau dessiné est celui des actions de l'écran, et toute touche hors
de celles-ci laisse l'écran inchangé.

**Une liste de numéros se lit d'une seule façon** (v0.39.0, décidé avec
l'utilisateur, 19 novembre 2026 ; `bob/selection.py`). Partout où BOB demande des
entrées par numéro — notes, rapports, tâches cron, adresses — il lit `all`, un
numéro, un intervalle `a-b`, ou plusieurs de ces formes séparées par des
virgules ; espaces et casse sont indifférents. Un numéro donné seul — isolé ou
dans une liste comme `1,7` — doit être une entrée : sinon toute la sélection est refusée, et le numéro est dit. Un
intervalle prend toutes les entrées qui existent entre ses bornes, trous
compris, et n'est refusé que s'il n'en contient aucune. Une sélection ne choisit
jamais rien du tout. Trouvé en le faisant : quatre lecteurs avaient quatre
règles — les notes refusaient un intervalle à trou (« 2-4 » sur les notes 1, 2 et
4 disait « pas de note 3 », trouvé par l'utilisateur), la liste des rapports en
mode texte abandonnait sans un mot un numéro inconnu, la liste des tâches en mode
texte refusait un intervalle dépassant la fin et tout mélange de formes, le
carnet d'adresses en mode texte plafonnait un intervalle à mille numéros (et
supprimait sans rien demander). *Gardé :* les formes · un numéro qui n'est pas
une entrée · un intervalle à trous et au-delà de la fin · un intervalle vide ·
les listes en mode texte.

**Les noms de comptes et les termes d'action ont leur couleur** (v0.43.0,
demandé par l'user les 22 et 23 novembre 2026, pour la lecture). Partout où un
écran montre un compte — l'équipe, les comptes à ajouter, l'auteur d'une ligne
de journal ou d'une note, l'opérateur de `--fix --apply` — le nom est en cyan
(`ACCOUNT`). Dans les journaux (`team`, `cron`, `admin`), le terme qui dit ce
qui a été fait prend la couleur de son effet :

| Couleur | Termes |
|---|---|
| vert (`POSITIVE`) | ce qui ajoute ou active — `init`, `grant`, un audit planifié créé, une adresse ajoutée, une catégorie `on`, `unignore` |
| rouge (`NEGATIVE`) | ce qui retire, désactive ou alerte — `revoke`, `remove`, un audit planifié supprimé, une adresse retirée, un rapport supprimé, une catégorie `off`, `ignore`, `reset_baseline`, une déclaration ou un réglage modifiés hors de BOB, une action faite hors d'un périmètre déclaré |
| jaune (`ACCENT`) | le reste — l'horaire ou les adresses d'un audit planifié modifiés, `reconfigure`, les essais de courriel et de webhook, `install_completion`, une tentative abandonnée, une action non attribuée |

Dans la liste du journal de `--fix --apply`, le statut de chaque commande prend
les mêmes couleurs (appliquée en vert, échec en rouge, le reste en jaune) et la
commande elle-même est en violet (`VERBATIM`), comme dans son détail. Une ligne
de journal se lit « action — détails » : l'action est toujours là où l'œil
commence. Le texte porte des marques autour d'un nom ou d'un terme
(`bob/_names.py` : SO pour un nom, DC1/DC2/DC3 pour un ton, DC4 pour une commande, SI pour fermer) ;
une seule fonction les dessine, `bob/tui/fixlog.put_marked`, que tout écran
dessinant une telle ligne appelle — l'aperçu d'un rapport dessinait jadis ses
lignes lui-même et affichait `^Nalice^O` (trouvé par l'user). Toute sortie texte
— `--fix-journal`, `--journals show`, `--team-journal`, un menu numéroté, un
tube — retire les marques. La ligne sous le curseur garde la couleur unique de
la sélection. *Gardé :* le terme de chaque ton · la paire de chaque ton ·
l'auteur d'une note dans l'aperçu · aucune marque dans une sortie texte.

**Seul Échap revient ; une action reste sur son écran** (v0.43.0, demandé par
l'user le 22 novembre 2026). Une touche qui agit — Entrée qui applique les
cases cochées, `d` qui retire, `n` qui ajoute — laisse l'écran en place, relu
depuis ce qui est désormais déclaré, son résultat sur la ligne de contexte.
Sortir appartient à Échap seul (et à `q` sur un écran d'accueil, qu'annonce
`LANDING_EXIT`). Trouvé en le faisant : Entrée sur « Ce qui est enregistré » de
`--manage-team` appliquait, puis revenait à l'écran précédent. *Gardé :*
l'image qui suit Entrée est le même écran, ses cases relues.

**Une liste marque comme toutes les listes** (la liste des rapports de
`--manage-logs`, v0.32.0 ; `--manage-team`, v0.43.0). Les entrées sont
numérotées ; Espace en marque une, `a` les marque toutes ; dès qu'une est
marquée, `u` retire les marques et le bandeau le dit ; un ✓ devant le numéro
montre la marque. `d` agit sur les entrées marquées — sans marque, il demande
lesquelles, lues comme toute sélection (`2`, `1,3`, `2-4`, `all`) — et confirme
en les nommant. Entrée sur une liste de choix prend les marquées, sinon celle
sous le curseur.

**Au retour, la sélection reste sur l'entrée quittée** (v0.43.0, demandé par
l'user le 23 novembre 2026). Échap depuis un écran ouvert depuis une liste
ramène à cette liste, le curseur sur l'entrée ouverte — par son nom quand la
liste peut changer entre-temps (un membre ajouté ou retiré), au même rang si
l'entrée a disparu. Vérifié écran par écran : l'accueil et la liste de
l'équipe de `--manage-team`, l'accueil et la liste des dossiers de
`--manage-logs` ne le faisaient pas (corrigés) ; la liste des rapports, les
journaux, les sélecteurs de `--explain` et les listes de `--manage-cron` le
faisaient. *Gardé :* les quatre corrigés.

**Une ligne vide sous le bandeau d'en-tête** (v0.43.0, demandé par l'user le
23 novembre 2026). Sur chaque écran, la ligne 0 est le bandeau et la ligne 1
reste vide — que l'on fasse défiler ou non ; le contenu commence à `BODY_TOP`
(`bob/tui/_chrome.py`), et la hauteur du contenu vaut
`h - BODY_TOP - chrome_height(...)`. Un écran n'ajoute pas de ligne vide à lui
en tête. Trouvé en le faisant : les journaux, le journal de `--fix --apply`,
`--explain`, l'aperçu d'un rapport et la liste des dossiers dessinaient juste
sous le bandeau ; d'autres avaient leur propre ligne vide en tête, qui
disparaissait au défilement. *Gardé :* le dessin commun (défilé aussi),
l'aperçu, les listes de `--explain`, `--manage-team`.

**Les colonnes s'alignent** (v0.43.0, demandé par l'user le 23 novembre 2026).
Dans toute liste que BOB affiche ou dessine — un journal, l'équipe, ce qui est
enregistré, le carnet d'adresses, les audits planifiés —, un champ qui suit un
champ de longueur variable commence dans une seule colonne : le champ d'avant
est complété jusqu'au plus long de la liste affichée (ou jusqu'à une largeur
fixe quand la liste est dessinée morceau par morceau), mesuré sur le texte
visible — jamais sur les marques de couleur — et le complément reste hors de
la couleur. Une ligne trop longue pour l'écran reprend sous sa dernière colonne
— après son dernier groupe d'au moins deux espaces —, jamais sous le début de
la ligne. Une ligne de journal complète son action (la partie avant « — »)
jusqu'à la plus longue action du journal, son auteur jusqu'au plus long
auteur. Trouvé en le faisant : dans le journal d'équipe, comptes et attributs
suivaient la longueur du mot d'avant ; dans le journal cron, les détails
suivaient la longueur de l'action ; le « NON enregistré » français dépassait
la colonne fixe de `--journals`. *Gardé :* les journaux team, cron et admin,
`--team`, `--journals`, le carnet d'adresses.

**Les deux surfaces s'accordent sur le sens.** L'orange marque ce qui est sous
l'attention (ligne de curseur, bandeau de touches) ; le violet marque ce qui
doit être reproduit à l'identique, des deux côtés. `VERBATIM` a été ajoutée en
v0.16.4 parce que la convention s'arrêtait à la frontière curses sans raison
énoncée : les mêmes lignes qui étaient violettes dans `bob --explain` se
lisaient comme de la prose ordinaire dans l'assistant.

Dans un bloc `HOW TO FIX`, c'est l'indentation qui marque la matière, de façon
constante sur toutes les clés (locale anglaise, 16 octobre 2026 : 903 lignes
indentées contre 636 étapes numérotées, le reste étant notes et prose). Peindre un bloc entier en violet a été essayé et a vidé la
couleur de son sens : les deux tiers d'un bloc sont de la prose.

L'orange comme le violet se replient sur l'approximation la plus proche en 8
couleurs plutôt que de disparaître, et chaque paire dégrade en attribut
(`A_REVERSE`, `A_BOLD`, `A_UNDERLINE`) sur un terminal sans couleur du tout.

*Gardé :* aucun `init_pair` hors de `_palette.py` · la ligne de curseur et le
bandeau ne partagent jamais un fond · une ligne marquée est rouge sur tous les
écrans.

---

## 3. Symboles

| Symbole | Signifie |
|---|---|
| `✔` | un résultat OK, un correctif appliqué |
| `✖` | une alerte, un refus, un correctif non appliqué |
| `⚠` | un avertissement |
| `ℹ` | une information — et, devant une commande, qu'elle ne fait que *diagnostiquer* |
| `→` | devant une commande, qu'elle *change l'état* |
| `•` | un élément d'une liste que l'opérateur doit traiter lui-même |

`→` et `ℹ` devant une commande sont la moitié visible de `cmd_type` : `fix`
dessine `→`, `check` dessine `ℹ`. Ce champ décide aussi si `--fix --apply` a le
droit d'exécuter la commande, donc le symbole et le comportement viennent d'un
seul endroit.

---

## 4. Boîtes et filets

Deux styles, une règle :

* **double `╔═╗`** — une boîte de synthèse : un résultat de haut niveau.
  `print_titled_box`, `print_summary_box`, l'en-tête de l'écran des correctifs.
* **simple `┌─┐`** — un en-tête de section : la structure d'une exécution.
  `print_section`.

Les modules qui *analysent* des rapports enregistrés reconnaissent les deux, ce
qui n'est pas un choix de style.

---

## 5. Texte atteignant un terminal

`Finding.__post_init__` retire les séquences ANSI et les caractères de contrôle
de `message`, `detail`, `note` et `cmd`. **N'assainissez pas vous-même le texte
d'un constat** — c'est le goulot, et c'est pourquoi un nom de processus lu dans
`ss` ne peut pas porter une séquence d'échappement jusqu'à la sortie d'un audit
lancé en root.

Une donnée qui atteint le terminal *hors* d'un `Finding` — un nom d'hôte, un
domaine, un nom de conteneur — passe par `output.sanitize()` au point où elle est
lue. Il y a plusieurs endroits de ce genre et ce sont les fragiles : un nouveau
ajouté sans l'appel serait un vecteur d'échappement que rien ne verrait.

---

## 6. Largeur

La sortie d'aide est plafonnée à 100 colonnes **visibles**. Les séquences
d'échappement occupent zéro colonne et doivent être retirées avant la mesure —
`\x1b[1m…\x1b[0m` fait huit caractères que `len()` compte et qu'un terminal ne
montre pas.

---

## 7. Conventions de code

### Pattern snapshot / check

Chaque module de vérification suit strictement ce pattern :

```python
@dataclass
class XxxSnapshot:
    # Données brutes collectées du système
    field_a: str
    field_b: int

    @classmethod
    def from_system(cls) -> "XxxSnapshot":
        # Appels subprocess ici — UNIQUEMENT ici
        data = _run("command", "arg")
        return cls(field_a=data, field_b=0)


def check_xxx(snapshot: XxxSnapshot, t=None) -> CheckResult:
    # Logique pure — JAMAIS d'appels subprocess ici
    _t = t if t is not None else _identity_t
    result = CheckResult()
    # ...
    return result
```

**Règle absolue :** `check_xxx()` ne fait jamais appel à subprocess. Toute la collecte est dans `from_system()`.

**Depuis la v0.14.1 — trois règles qui découlent de la barrière d'isolation :**

1. **Enregistrer le collecteur, pas le snapshot.** `runner._sec` prend
   `XxxSnapshot.from_system` (un callable), jamais `XxxSnapshot.from_system()`
   (un objet déjà construit). Le collecteur est invoqué *à l'intérieur* de la
   barrière : une panne à cet endroit dégrade la section au lieu d'interrompre
   l'audit — et une section exclue par `--check` / `--skip` / le profil ne coûte
   rien. Passer un snapshot pré-construit déplace silencieusement la collecte
   hors de la barrière ; `tests/test_v0141_robustness.py` fait échouer le build
   si un site d'appel le fait. (`hardening_snapshot` et `ipv6_snapshot` sont
   les exceptions — tous deux sont renvoyés dans `ChecksResult` pour
   `--json-full`, donc collectés d'emblée, dans la barrière `_core` plutôt que
   dans celle de `_sec`.)

2. **Lire les fichiers via `bob._atomic.read_text_capped()`**, pas `read_text()`.
   Il refuse tout ce qui n'est pas un fichier régulier (périphérique, FIFO,
   répertoire) et borne la lecture, et il déclare `errors="replace"` pour qu'un
   octet non-UTF-8 dans un fichier système dégrade au lieu de lever. Un
   `read_text()` nu dans un bloc `except OSError` est rejeté par un garde AST
   qui balaie tout le paquet.

3. **Ne pas assainir soi-même le texte des constats.** `Finding.__post_init__()`
   retire les séquences ANSI et les caractères de contrôle de `message` /
   `detail` / `note` (et de `cmd`, en préservant les sauts de ligne), au point
   unique par lequel passe chaque constat. Interpole directement les valeurs
   venues du système.

Un check qui lève n'est plus fatal, mais il n'est pas gratuit pour autant : la
section est rapportée comme un constat INFO `<section>.unavailable` et listée
dans le `degraded_sections` du JSON. Dégrader proprement dans le check reste
préférable à s'en remettre à la barrière.

### CheckResult

```python
result = CheckResult()

result.ok(message=_t("clé"))                          # ✔ constat
result.warn(message=_t("clé"), nature="improvement")  # ⚠ constat
result.alert(message=_t("clé"), nature="action",      # ✖ constat
             cmd="sudo ufw ...")
result.info(message=_t("clé"))                        # ℹ constat

result.add_deduction(
    reason=_t("clé"),
    points=2,
    context="local",   # ou "public"
    key="xxx.something",
)

# forme habituelle depuis la v0.5.x : le constat et sa déduction en un appel
result.warn_with_deduction(key="xxx.something", message=_t("xxx.something"), points=1)
```

`warn()` et `alert()` ne prennent pas de `points` ; une déduction porte toujours une `key`.

### Natures des constats

| Nature | Signification | Bloc résumé |
|---|---|---|
| `"action"` | Correction requise | *Action requise* |
| `"improvement"` | Amélioration possible | *Améliorations possibles* |
| `"structural"` | Configuration normale mais notable | Pas de bloc à elle — affichée dans sa section |
| `None` | Informatif pur | Non affiché dans le résumé |

### Fonction de traduction

Toujours passer `t` en paramètre avec fallback identity :

```python
def check_xxx(snapshot, t=None) -> CheckResult:
    _t = t if t is not None else _identity_t
```

Cela permet de tester sans initialiser i18n :

```python
result = check_firewall(make_status())          # clés brutes dans les messages
result = check_firewall(make_status(), t=my_t)  # traduction personnalisée
```

### Subprocess

Toujours par les aides partagées de `bob/checks/_run.py` — `_run()` pour la
sortie, `run_result()` quand le code de retour compte — que chaque module de
vérification importe :

```python
from bob.checks._run import _run, _C_LOCALE_ENV

out = _run("ufw", "status", timeout=10)   # pas de shell, un délai, "" sur tout échec
```

Ne jamais appeler `subprocess` directement depuis un check, ni laisser une
exception subprocess remonter.

### Tests

Chaque module de vérification est couvert par des tests — dans
`tests/test_<module>.py` pour la plupart, et pour les autres dans le fichier
nommé d'après la version qui a ajouté le check (`tests/test_v0170_raspberry_pi.py`,
`tests/test_v0210_polkit.py`, `tests/test_v0250_kubernetes_node.py`, …). Les
tests de checks :

- Ne font aucun appel système
- Construisent les snapshots directement
- Testent la logique pure dans `check_xxx()`
- Testent les helpers de parsing séparément

Structure type :

```python
def make_snapshot(**overrides) -> XxxSnapshot:
    defaults = dict(field_a="default", field_b=0)
    defaults.update(overrides)
    return XxxSnapshot(**defaults)

def test_nominal_case():
    snap = make_snapshot(field_a="value")
    result = check_xxx(snap)
    assert "ok" in [f.level.value for f in result.findings]
```

---

## 8. Versionnage

Les versions sont en **SemVer** `MAJEUR.MINEUR.CORRECTIF`, **sans préfixe `v`** —
dans le code, les tags git, et tout ce que BOB affiche. La version canonique vit
dans `bob/__init__.py` (`__version__`) et `pyproject.toml` ; PyPI et SemVer
l'appellent `0.21.0`, donc le banner, `--version`, l'en-tête du rapport/markdown,
le webhook et la barre de titre TUI affichent `0.21.0`, jamais `v0.21.0`. Les
versions d'outils tiers (ufw, firewalld) sont affichées pareil — nues.

Une release est un tag git nommé d'après la version **sans préfixe** (`0.21.0`,
pas `v0.21.0`) ; le workflow de publication se déclenche dessus. La forme legacy
`v*` n'est gardée dans le trigger que pour que la dernière release taguée en v
(`v0.20.5`) publie encore — tout tag à partir de v0.21.0 est sans `v`.
`tests/test_v0210_semver_no_v_prefix.py` épingle les surfaces d'affichage et
`tests/test_doc_version_consistency.py` les badges.

**Branches.** `main` ne porte que des versions publiées ; le travail en cours
entre deux versions vit sur `unstable`. Une version s'assemble sur `unstable`,
arrive sur `main` sans commit de fusion, et se tague sur `main` — le workflow de
publication refuse un tag dont le commit n'a jamais tourné au vert sur `main`.
Détails dans [CI_FR.md](CI_FR.md#branches).

**Le texte de `--version` est-il un contrat stable ?** Non. La *chaîne* de version
est une surface d'affichage, pas une partie du contrat de compatibilité de BOB.
Elle a changé exactement une fois — le `v` a été retiré en 0.21.0 — et est
désormais figée sur le cœur SemVer nu. Le contrat CLI stable, c'est : les codes de
sortie, le schéma JSON (`schema_version` et ses clés), les noms d'options et les
clés de constat — ceux-là ne changent pas sans incrément MAJEUR/MINEUR et note de
changelog. L'abandon d'une version de Python supportée est aussi BREAKING : il n'a lieu que
dans une release étiquetée BREAKING, au moins 6 mois après la fin de vie upstream de
cette version (voir README_TECH, *Politique de support Python*). Un script qui parsait `bob --version` en codant en dur le `v` (ou
`sed 's/^v//'`) doit lire la forme nue à partir de 0.21.0 ; un script qui a besoin
d'une version stable machine doit lire `--format json` (`schema_version`) plutôt
que de gratter la sortie humaine. C'est explicité pour que le dé-`v` soit une
décision ponctuelle et documentée, pas un précédent ouvert pour tripatouiller le
texte de version.

---

## 9. Localisation, explain, et les registres qu'un check touche

Le pattern Snapshot/check (§7) est la moitié d'un nouveau check. L'autre moitié, c'est
le câbler dans chaque registre qui doit s'accorder avec lui. En oublier un fait
échouer une garde ; oublier le compteur fait échouer
`test_v0170_doc_counters_sweep` / `test_v0211_live_count_claims`.

### Clés locale (`bob/locales/{en,fr}.json`)

Chaque chaîne visible par l'opérateur est une clé, et les deux fichiers ont un
**ensemble de clés strictement égal** (`test_i18n.py`) — ajouter une clé à l'un,
l'ajouter à l'autre, ou la garde de parité échoue. Un check nommé `xxx` touche
typiquement trois endroits dans chaque fichier :

- le bloc **header de section** (`"xxx": "TITRE DE SECTION"`),
- le bloc **description de section** (une ligne sous le header),
- un bloc **messages** (`"xxx": { "finding_key": "…", … }`), dont les clés sont les
  suffixes `.key` que le check émet (`xxx.something`).

Un constat WARN/ALERT demande aussi une entrée **explain** (ci-dessous). Le total de
clés est documenté dans SNAPSHOT et épinglé au live — le mettre à jour quand on ajoute des
clés.

Interpoler avec des placeholders `{name}`, jamais des f-strings dans le JSON. Ne pas
mettre une commande spécifique à une distribution (`apt install …`) dans un
*message* : le champ `cmd` du constat porte la commande spécifique à l'hôte, et
`test_v0170_distro_paths.py` rejette un gestionnaire de paquets nommé dans la prose
d'un message (les blocs explain qui nomment la famille sont exemptés).

**Les libellés de services restent en anglais à dessein.** Les 38 libellés
de `services.json` (`Samba (Windows file sharing)`, …) ne sont pas traduits — une
exception délibérée et documentée, pas une dérive.

### Clés `--explain`

Chaque clé de constat WARN ou ALERT doit avoir une entrée `--explain` correspondante
(`test_explain_coverage.py`), avec `title` / `why` / `how` dans les **deux** locales.
Un check INFO-only n'a **pas** besoin d'explain (c'est pourquoi `module_blacklist`,
`dev_privileged` et `package_integrity` n'en ont pas). Les clés explain suivent la
convention de nommage `prefix.name` épinglée par `test_explain_naming_convention.py`
(préfixes connus + comptes). L'ensemble explain est câblé dans `bob/explain.py`
(`_EXPLAIN_GROUPS`), les blocs explain des locales, et `bob/data/bob.bash-completion`
(`_EXPLAIN_KEYS`).

### Références CIS (`bob/data/cis_refs.json`)

Une clé de constat peut porter une référence CIS/benchmark. Les numéros sont
**générés depuis ComplianceAsCode par le nom de la règle**, jamais tapés à la main
(voir DOCTRINE principe 21) ; le breakdown par benchmark est épinglé par
`test_v0163_readme_tech_claims.py`.

### Clés de visibilité (`bob/visibility.py`)

Un constat qui signifie « ceci n'a pas pu être vérifié » (`xxx.unreadable`,
`xxx.unknown`, `xxx.tool_missing`, `xxx.timed_out`) appartient à l'ensemble de
visibilité, pour que le compte « N non vérifiés » soit honnête (DOCTRINE principe 2).
Une section qui *lève* est dégradée en `xxx.unavailable` par la barrière de faute
automatiquement — celle-là n'est pas listée par son nom.

### Mapping de domaine (`bob/domain_scores.py`)

Le préfixe de chaque section mappe vers l'un des **6 domaines de score** via
`_PREFIX_TO_DOMAIN`, et le mapping doit correspondre au **groupe d'affichage** de la
section (`test_v0200`). Un nouveau check ajoute une entrée.

### Enregistrement et complétion

La section est enregistrée dans `runner.py` (`_SECTIONS`, avec son flag `always_on`)
et dispatchée via `_sec` (§7). Ajouter son nom à `bob/data/bob.bash-completion`
(`_SECTIONS`). Une section exclue du run par défaut (comme `package_integrity` sous
`--exhaustive`) reste une section enregistrée et filtrable — elle est gatée à son site
d'appel, pas omise du registre.

### Garde + mutation + compteurs

Enfin : une garde (`tests/test_vXXXX_<check>.py`), sa mutation dans
`tests/mutations.py` (DOCTRINE principe 13), et les compteurs documentés mis à jour
(sections, check modules, `_PREFIX_TO_DOMAIN`, total locale, explain/CIS si touchés,
compte de fichiers tests dans SNAPSHOT). Le sweep donne les valeurs live exactes ; un
nombre coïncident à côté d'un nom non surveillé va dans le `_COINCIDENCES` du sweep.

## 10. Glossaire

Les mots que ce projet emploie pour les parties d'un audit, chacun avec le code
qui le définit. Ils ne sont pas interchangeables : « section » et « check » en
particulier se disent souvent l'un pour l'autre, et une phrase qui les mélange
se trompe en général sur l'un des deux.

| Terme | Sens | Où il vit |
|---|---|---|
| **module de check** | Un fichier sous `bob/checks/` qui collecte un sujet et le juge (le compteur de SNAPSHOT). Un module peut servir plusieurs sections. | `bob/checks/*.py`, `bob/checks/ssh/` |
| **snapshot** | Ce qu'un module a lu sur l'hôte, collecté par `from_system()`, qui ne lève jamais d'exception. Les tests le construisent à la main. | dataclasses `XxxSnapshot` |
| **check** | La fonction pure `check_xxx(snapshot, t)` qui transforme un snapshot en `CheckResult`. Elle ne lit rien sur l'hôte. | fonctions `check_*` |
| **section** | Une étape nommée d'un audit, avec son propre titre à l'écran ; ce que `--check` et `--skip` sélectionnent. Le runner applique le `CheckResult` de chaque section sous ce nom. | `emit_section()`, `engine.apply(…, section=…)` dans `bob/runner.py` |
| **constat** (finding) | Une ligne d'un `CheckResult` : un niveau (OK / INFO / WARN / ALERT), une clé, un message, et au besoin un détail, une commande et une déduction. | `Finding`, `FindingLevel` dans `bob/scoring.py` |
| **clé** | L'identifiant pointé d'un constat, `<préfixe>.<nom>` (`ssh.password_auth`). C'est ce qu'indexent `--explain`, `ignore.yml`, la table CIS et la table des domaines. | chaque argument `key=` |
| **déduction** | Les points qu'un constat retire au score de son domaine. Une INFO n'en porte jamais. | `warn_with_deduction`, `alert_with_deduction`, `add_deduction` |
| **plafond** (cap) | Une borne haute qu'un constat impose au score de son domaine (un UFW inactif, ou l'absence de tout pare-feu actif, maintient *Pare-feu & Réseau* à 3/10) ; le score global est la moyenne des domaines, il n'est donc pas plafonné lui-même. | `CheckResult.set_cap` |
| **clé de visibilité** | Une clé qui dit qu'une section n'a pas pu être lue. Sa présence fait du score un plafond (`≤ N/10`) — inconnu n'est pas propre. | `VISIBILITY_KEYS` dans `bob/visibility.py` |
| **domaine** | L'un des six périmètres scorés — pare-feu & réseau, exposition & services, contrôle d'accès, durcissement système, santé & résilience, outils de détection — chacun noté de 0 à 10 ; une clé y appartient par son préfixe. | `DOMAINS`, `_PREFIX_TO_DOMAIN` dans `bob/domain_scores.py` |
| **groupe** | Le titre à l'écran qui rassemble les sections d'un domaine. Depuis v0.20.0, groupes et domaines sont les mêmes six. | `emit_group()` dans `bob/runner.py` |

---

© 2026 Cédric Clauzel
