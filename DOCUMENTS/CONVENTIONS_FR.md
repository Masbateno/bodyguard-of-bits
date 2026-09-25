*[Read in English](CONVENTIONS.md)*

# BOB — Conventions

Comment ce projet fait les choses, en un seul endroit : ce que veut dire une
couleur, ce que veut dire un symbole, et les motifs de code qu'un check doit
suivre.

Tout ce qui suit était vrai à l'écriture, et l'essentiel est désormais vérifié.
La distinction compte : ce projet a deux fois trouvé une convention vivant dans
trois modules qui se trouvaient d'accord — la charte curses a partagé son cyan
entre la ligne de curseur et le bandeau pendant neuf versions, faute de quoi que
ce soit qui les compare. Une règle vérifiable mécaniquement porte le nom de sa
garde ; une règle qui ne l'est pas le dit.

---

## 1. Couleur — sortie terminal

Seize couleurs ANSI sont définies dans `bob/output.py` ; quatorze portent un
sens. La table fait autorité, et aucun module ne fabrique lui-même une séquence
d'échappement.

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

Neuf paires, définies une seule fois dans `bob/tui/_palette.py`. **N'appelez pas
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

**Les deux surfaces s'accordent sur le sens.** L'orange marque ce qui est sous
l'attention (ligne de curseur, bandeau de touches) ; le violet marque ce qui
doit être reproduit à l'identique, des deux côtés. `VERBATIM` a été ajoutée en
v0.16.4 parce que la convention s'arrêtait à la frontière curses sans raison
énoncée : les mêmes lignes qui étaient violettes dans `bob --explain` se
lisaient comme de la prose ordinaire dans l'assistant.

Dans un bloc `HOW TO FIX`, c'est l'indentation qui marque la matière — 664
lignes indentées contre 527 étapes numérotées et 74 notes, de façon constante
sur toutes les clés. Peindre un bloc entier en violet a été essayé et a vidé la
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

Une donnée qui atteint le terminal *hors* d'un Finding — un nom d'hôte, un
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
   si un site d'appel le fait. (`hardening_snapshot` est l'exception documentée
   — il alimente aussi `ChecksResult` pour le bloc sysctl de `--json-full`.)

2. **Lire les fichiers via `bob._atomic.read_text_capped()`**, pas `read_text()`.
   Il refuse tout ce qui n'est pas un fichier régulier (périphérique, FIFO,
   répertoire) et borne la lecture, et il déclare `errors="replace"` pour qu'un
   octet non-UTF-8 dans un fichier système dégrade au lieu de lever. Un
   `read_text()` nu dans un bloc `except OSError` est rejeté par un garde AST
   qui balaie tout le paquet.

3. **Ne pas assainir soi-même le texte des findings.** `Finding.__post_init__()`
   retire les séquences ANSI et les caractères de contrôle de `message` /
   `detail` / `note` (et de `cmd`, en préservant les sauts de ligne), au point
   unique par lequel passe chaque finding. Interpole directement les valeurs
   venues du système.

Un check qui lève n'est plus fatal, mais il n'est pas gratuit pour autant : la
section est rapportée comme un finding INFO `<section>.unavailable` et listée
dans le `degraded_sections` du JSON. Dégrader proprement dans le check reste
préférable à s'en remettre à la barrière.

### CheckResult

```python
result = CheckResult()

result.ok(message=_t("clé"))                          # ✔ finding
result.warn(message=_t("clé"), nature="improvement")  # ⚠ finding
result.alert(message=_t("clé"), nature="action",      # ✖ finding
             cmd="sudo ufw ...")
result.info(message=_t("clé"))                        # ℹ finding

result.add_deduction(
    reason=_t("clé"),
    points=2,
    context="local",   # ou "public"
)
```

### Natures des findings

| Nature | Signification | Bloc résumé |
|---|---|---|
| `"action"` | Correction requise | *Action requise* |
| `"improvement"` | Amélioration possible | *Améliorations possibles* |
| `"structural"` | Configuration normale mais notable | *Configuration normale* |
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

Toujours via le helper `_run()` local à chaque module :

```python
def _run(*args: str) -> str:
    try:
        proc = subprocess.run(
            list(args), capture_output=True, text=True, timeout=10,
        )
        return proc.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""
```

Ne jamais laisser une exception subprocess remonter.

### Tests

Chaque module de vérification a son fichier de test correspondant. Les tests :

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

**Le texte de `--version` est-il un contrat stable ?** Non. La *chaîne* de version
est une surface d'affichage, pas une partie du contrat de compatibilité de BOB.
Elle a changé exactement une fois — le `v` a été retiré en 0.21.0 — et est
désormais figée sur le cœur SemVer nu. Le contrat CLI stable, c'est : les codes de
sortie, le schéma JSON (`schema_version` et ses clés), les noms d'options et les
clés de constat — ceux-là ne changent pas sans bump MAJEUR/MINEUR et note de
changelog. Un script qui parsait `bob --version` en codant en dur le `v` (ou
`sed 's/^v//'`) doit lire la forme nue à partir de 0.21.0 ; un script qui a besoin
d'une version stable machine doit lire `--format json` (`schema_version`) plutôt
que de gratter la sortie humaine. C'est explicité pour que le dé-`v` soit une
décision ponctuelle et documentée, pas un précédent ouvert pour tripatouiller le
texte de version.

---

© 2026 Cédric Clauzel
