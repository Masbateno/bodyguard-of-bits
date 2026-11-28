*[Read in English](BACKLOG.md)* · *[Journal des modifications](CHANGELOG_FR.md)*

# BOB — Backlog

Ce qui est prévu ou en attente, trié par gravité. Chaque ligne est un point du backlog du mainteneur ; son identifiant ne change jamais (les numéros absents sont des points déjà traités : voir le [journal des modifications](CHANGELOG_FR.md)). **Prévu** donne la version visée, ou `pending` quand aucune n'est fixée.

Dernière mise à jour : 27 novembre 2026.

## Gravité

| Gravité | Ce que ça veut dire |
|---|---|
| 🔴 HAUTE | BOB peut donner un score faux : des points retirés ou accordés à tort. |
| 🟠 MOYENNE | BOB peut affirmer une chose fausse ou trop rassurante, sans point en jeu. |
| 🟡 BASSE | Texte imprécis, présentation, robustesse : le verdict reste juste. |
| 🔵 LIMITE | Ce que BOB ne lit pas, et le dit (le score devient un plafond). |
| ⚪ EXTERNE | Attend quelqu'un d'autre. |
| 🟢 ÉVOLUTION | Demandée ou à décider : pas un défaut du verdict actuel. |
| ⚫ LONG TERME | Utile, sans échéance. |

## Points ouverts

| Gravité | ID | Description | Prévu |
|---|---|---|---|
| 🟡 BASSE | B-053 | Aligner « plafond / ceiling » de l'aide et des écrans sur « seuil de rétention ». | 0.44.0 |
| 🟡 BASSE | B-054 | Garde contre le mktemp par test et contre les comptes de l'hôte dans les tests d'écran. | 0.44.0 |
| 🟡 BASSE | B-057 | README : le lien des périmètres d'équipe dit « qui peut faire quoi », plus que ce que font les périmètres. | 0.44.0 |
| 🟡 BASSE | B-026 | Test de la CI qui échoue exprès quand une image arrive en fin de support (prochaine échéance : 1er mai 2027). | pending |
| 🟡 BASSE | B-056 | Parité des langues : DISTRO_MATRIX.md et SNAPSHOT.md n'ont pas encore de version française. | pending |
| ⚪ EXTERNE | B-016 | Attendre CIS Fedora (brouillon) et le niveau 2 d'Ubuntu 26.04 chez ComplianceAsCode. | pending |
| 🟢 ÉVOLUTION | B-050 | Plafond réglable des journaux avec rotation chaînée (la partie rapports est publiée en 0.43.0). | 0.44.0 |
| 🟢 ÉVOLUTION | B-051 | Basculer d'un assistant à l'autre par raccourci (touches de fonction). | 0.44.0 |
| 🟢 ÉVOLUTION | [B-055](#annexe--b-055) | Repenser l'exécution en root (sudo) : collecte privilégiée minimale, tout le reste sous le compte de l'appelant, périmètres appliqués par Linux ; étapes 0 et 1 en 0.44.0, la suite après. | 0.44.0 |
| 🟢 ÉVOLUTION | B-052 | Blocs-notes d'équipe dans --manage-team : un ouvert à tous, un par compte, droits de lecture et d'écriture de chacun vers les autres posés par des ACL Linux. | 0.45.0 |
| 🟢 ÉVOLUTION | B-045 | Courriels au maître pour les actions hors périmètre (socle publié en 0.43.0) ; attend l'étape 3 de B-055. | pending |
| 🟢 ÉVOLUTION | B-046 | Fichiers sans empreinte enregistrée : fait pour Debian en 0.43.0, reste l'équivalent rpm. | pending |
| 🟢 ÉVOLUTION | B-047 | Bloc-notes secret d'équipe par un greffon vers un outil éprouvé (pass). | pending |
| 🟢 ÉVOLUTION | B-048 | Écran d'édition des fichiers de configuration (SSH puis Samba), avec validation et copies. | pending |
| 🟢 ÉVOLUTION | B-049 | Passation du rôle de maître, puis co-maîtres ; attend l'étape 3 de B-055. | pending |
| ⚫ LONG TERME | B-018 | Passer d'autres modèles de Raspberry Pi sur du vrai matériel. | pending |

Aucun point en 🔴 HAUTE, 🟠 MOYENNE ni 🔵 LIMITE aujourd'hui.

Annexe ci-dessous : [B-055](#annexe--b-055).

## Annexe — B-055

**État (27 novembre 2026, 0.44.0) : les étapes 0 et 1 ci-dessous sont faites et mesurées en
0.44.0 ; les étapes 2 à 4 n'ont pas encore de version.** Les points de « Ce que montre le code »
décrivent la 0.44.0, d'après la lecture de son code, ceux des greffons mesurés ; tant que la
conception ne change pas davantage, tenez-les pour vrais.

### Ce que montre le code

- **Un audit tourne en root du début à la fin.** `sudo bob` est exigé, et BOB ne rend jamais
  les droits de root ensuite.
- **Root fait aussi un travail qui n'en a pas besoin** : lire et analyser des fichiers que des
  utilisateurs ordinaires peuvent écrire, écrire dans les dossiers personnels, envoyer le
  webhook et les courriels, dessiner les écrans quand on les ouvre avec `sudo`. Deux correctifs
  de sécurité passés venaient de cette famille : 0.26.1 (en root, BOB suivait un lien
  symbolique dans le dossier personnel de l'utilisateur) et 0.38.0 (une configuration
  appartenant à un utilisateur, désormais inspectée avant que root ne la lise).
- **Les greffons ne tournent plus en root (0.44.0).** Sous `sudo`, BOB charge les greffons
  trouvés dans `~/.config/bob/checks.d/` de l'utilisateur appelant. Jusqu'à la 0.43.0, l'enfant du
  bac à sable gardait les droits de root (**mesuré** : un greffon rapportait son propre identifiant
  0). Depuis la 0.44.0, l'enfant prend l'uid et les groupes de l'appelant avant de lire le greffon
  (**mesuré** sur Linux Mint 22.3, Fedora 44 et Alpine 3.24), et root ne suit plus un lien
  symbolique pour en ouvrir un. Le code de BOB dit toujours que ce bac à sable n'est pas une
  frontière de sécurité.
- **Autoriser quelqu'un à lancer `sudo bob` revient donc à lui donner root.** Une règle
  sudoers qui n'autorise que `bob` ne limite pas cette personne à l'audit.
- **Les périmètres d'équipe (0.43.0) ne sont pas un contrôle d'accès.** Ils annoncent,
  redemandent et consignent une action hors d'un périmètre déclaré ; ils n'empêchent rien. Tant
  que chaque membre lance `sudo bob`, aucun périmètre ne peut être appliqué.
- **Les journaux sont des témoins locaux.** Root peut réécrire un journal comme le journal
  système local ; contre cela, il faut des journaux tenus sur un autre hôte.
- **Les audits programmés tournent en root** (une ligne `root` dans `/etc/cron.d`, ou la
  crontab de root là où il n'y a pas de `/etc/cron.d`).
- **La plupart des installations ne sont pas confinées.** Seul l'empaquetage Debian porte un
  profil AppArmor ; une installation par pip ou pipx n'en a aucun.

### Première mesure : BOB sans root (26 novembre 2026)

Sur une machine de test, le même audit lancé en root, puis avec deux comptes ordinaires (l'un
dans le groupe `adm`, l'autre dans aucun groupe). Sans root, BOB dit déjà « non lu » presque
partout : 12 constats de plus le disent, et la fourchette du score s'élargit (7–8 en root, 2–8
sans root) au lieu de cacher ce qu'il n'a pas pu voir. Trois endroits ne le faisaient pas, et ont
été corrigés en 0.44.0 (étape 1) : le journal d'UFW était dit « introuvable » alors qu'il existe mais n'a pas
pu être lu ; le `~/.ssh` de root était dit « introuvable » pour la même raison ; et le mot de
passe de GRUB passait sous silence quand `grub.cfg` n'a pas pu être lu. Mesuré depuis sur Fedora
44 et Alpine 3.24 aussi : un endroit de plus là — le journal d'authentification, vu en partie, lu
comme « aucune connexion » — corrigé lui aussi. Ces passages sans root ont servi à trouver ces
endroits ; l'audit lui-même reste réservé à root (décidé le 27 novembre 2026) : sans root, il était
incomplet, et sur Fedora trompeur — deux domaines entiers non lus, le score monté de 8 à 9.

### Que faire en attendant

- N'autorisez `sudo bob` qu'aux personnes à qui vous confieriez root.
- Avant de lancer `sudo bob`, regardez les greffons de votre `~/.config/bob/checks.d/` : seul du
  code de confiance doit s'y trouver.
- Servez-vous des périmètres d'équipe comme d'un registre de qui a fait quoi, pas comme d'une
  barrière.
- Signalez tout ce que vous trouvez à ce sujet par [SECURITY_FR.md](SECURITY_FR.md).

### Ce qui est prévu

La direction : root seulement pour lire ce qui l'exige ; tout le reste sous le compte de
l'utilisateur appelant ; les droits de l'équipe portés par Linux lui-même (groupes,
propriétaires des fichiers, sudoers), que BOB lit et dit au lieu de les imiter.

- **Étape 0 — un inventaire mesuré** *(fait, 0.44.0)* : pour chaque section, ce qu'elle lit et
  pourquoi elle a besoin de root ; le point des greffons ci-dessus, mesuré.
- **Étape 1 — une lecture refusée n'est pas une absence, et des greffons sans root** *(fait,
  0.44.0)* : un fichier qui existe mais ne peut être lu est signalé non lu, jamais pris pour une
  absence ; les greffons tournent avec l'uid et les groupes du compte appelant (derrière sudo ou
  doas), pas ceux de root, et ne sont jamais ouverts à travers un lien. L'audit lui-même reste
  réservé à root.
- **Étape 2 — séparation des privilèges** : un collecteur root minimal ; l'analyse, le score,
  les rapports, les écrans et le réseau sous le compte de l'appelant. Les scores et les codes de
  sortie de `sudo bob` restent les mêmes.
- **Étape 3 — l'équipe portée par Linux** : les attributs deviennent des groupes Linux, les
  rapports sont partagés par groupe, `--fix --apply` passe par le `sudo` de la personne. Un
  périmètre devient appliqué, plus seulement déclaré.
- **Étape 4 — confinement** : audits programmés par une unité systemd aux capacités bornées ;
  un profil AppArmor hors de l'empaquetage Debian ; SELinux à étudier.

Les étapes 2 et 3 changeront probablement l'emplacement des rapports, des tâches programmées
et des journaux : ce sera annoncé comme BREAKING le moment venu.

---

© 2026 Cédric Clauzel
