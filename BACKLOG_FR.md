*[Read in English](BACKLOG.md)* · *[Journal des modifications](CHANGELOG_FR.md)*

# BOB — Backlog

Ce qui est prévu ou en attente, trié par gravité. Chaque ligne est un point du backlog du mainteneur ; son identifiant ne change jamais (les numéros absents sont des points déjà traités : voir le [journal des modifications](CHANGELOG_FR.md)). **Prévu** donne la version visée, ou `pending` quand aucune n'est fixée.

Dernière mise à jour : 26 novembre 2026.

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
| 🟡 BASSE | B-026 | Test de la CI qui échoue exprès quand une image arrive en fin de support (prochaine échéance : 1er mai 2027). | pending |
| 🟡 BASSE | B-056 | Parité des langues : DISTRO_MATRIX.md et SNAPSHOT.md n'ont pas encore de version française. | pending |
| ⚪ EXTERNE | B-016 | Attendre CIS Fedora (brouillon) et le niveau 2 d'Ubuntu 26.04 chez ComplianceAsCode. | pending |
| 🟢 ÉVOLUTION | B-045 | Courriels au maître pour les actions hors périmètre (le socle est publié en 0.43.0). | 0.44.0 |
| 🟢 ÉVOLUTION | B-049 | Passation du rôle de maître, puis co-maîtres. | 0.44.0 |
| 🟢 ÉVOLUTION | B-050 | Plafond réglable des journaux avec rotation chaînée (la partie rapports est publiée en 0.43.0). | 0.44.0 |
| 🟢 ÉVOLUTION | B-051 | Basculer d'un assistant à l'autre par raccourci (touches de fonction). | 0.44.0 |
| 🟢 ÉVOLUTION | B-052 | Bloc-notes d'équipe en clair, une entrée par compte, dans --manage-team. | 0.44.0 |
| 🟢 ÉVOLUTION | B-046 | Fichiers sans empreinte enregistrée : fait pour Debian en 0.43.0, reste l'équivalent rpm. | pending |
| 🟢 ÉVOLUTION | B-047 | Bloc-notes secret d'équipe par un greffon vers un outil éprouvé (pass). | pending |
| 🟢 ÉVOLUTION | B-048 | Écran d'édition des fichiers de configuration (SSH puis Samba), avec validation et copies. | pending |
| 🟢 ÉVOLUTION | [B-055](#annexe--b-055) | Repenser l'exécution en root (sudo) : collecte privilégiée minimale, tout le reste sous le compte de l'appelant, périmètres d'équipe appliqués par Linux. | pending |
| ⚫ LONG TERME | B-018 | Passer d'autres modèles de Raspberry Pi sur du vrai matériel. | pending |

Aucun point en 🔴 HAUTE, 🟠 MOYENNE ni 🔵 LIMITE aujourd'hui.

Annexe ci-dessous : [B-055](#annexe--b-055).

## Annexe — B-055

**État : rien de ce qui suit n'est encore mesuré.** C'est ce que montre la lecture du code de
BOB (version 0.43.0). La mesure est en cours. Tant qu'elle n'est pas faite et que la conception
n'a pas changé, tenez chaque point pour vrai. Aucune version n'est encore fixée pour ce
changement (`pending`).

### Ce que montre le code

- **Un audit tourne en root du début à la fin.** `sudo bob` est exigé, et BOB ne rend jamais
  les droits de root ensuite.
- **Root fait aussi un travail qui n'en a pas besoin** : lire et analyser des fichiers que des
  utilisateurs ordinaires peuvent écrire, écrire dans les dossiers personnels, envoyer le
  webhook et les courriels, dessiner les écrans quand on les ouvre avec `sudo`. Deux correctifs
  de sécurité passés venaient de cette famille : 0.26.1 (en root, BOB suivait un lien
  symbolique dans le dossier personnel de l'utilisateur) et 0.38.0 (une configuration
  appartenant à un utilisateur, désormais inspectée avant que root ne la lise).
- **Les greffons tournent en root.** Sous `sudo`, BOB charge les greffons trouvés dans
  `~/.config/bob/checks.d/` de l'utilisateur appelant et les exécute dans un processus enfant
  qui garde les droits de root. Le code de BOB dit lui-même que ce bac à sable n'est pas une
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

- **Étape 0 — un inventaire mesuré** *(en cours)* : pour chaque section, ce qu'elle lit et
  pourquoi elle a besoin de root ; le point des greffons ci-dessus, mesuré.
- **Étape 1 — sans root, honnêtement** : `bob` sans `sudo` audite ce qu'il peut et dit « non
  lu » pour le reste ; les greffons tournent avec les droits de l'appelant, même quand BOB est
  root.
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
