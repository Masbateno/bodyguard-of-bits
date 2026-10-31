*[Read in English](CI.md)*

# BOB — CI/CD, d'un push à un paquet sur PyPI

Ce qui tourne sur GitHub quand du code est poussé ou qu'une version est taguée,
avec quels droits, ce qui est épinglé et ce qui ne l'est pas. Écrit pour la
0.28.2, après un audit de toute la chaîne le 30 octobre 2026 : les réglages du
dépôt lus par l'API GitHub, les trois workflows lus ligne à ligne, le code de
chaque action lu au commit où elle est épinglée, les journaux de la publication
0.28.1 lus, et [zizmor](https://docs.zizmor.sh/) 1.31.1 lancé hors ligne comme
contre-vérification. Chaque changement a été mesuré avant d'être fait — dans
podman sur chaque image de la matrice, dans un environnement jetable pour le
build, en Release brouillon pour l'étape de Release.

## Les trois workflows

| Workflow | Déclenché par | Jobs | Jeton |
|---|---|---|---|
| `tests.yml` | chaque push et pull request | `lint` (ruff sur `bob/`), `build-backend-pin` (l'épinglage de setuptools doit mordre), `mutation` (chaque garde doit encore échouer quand son défaut revient), `pytest` sur Python 3.10 – 3.14 | lecture |
| `integration.yml` | un push sur `main`, une pull request vers `main`, à la main | `smoke` dans un conteneur de chaque distribution ci-dessous, `arm64` sous QEMU | lecture |
| `publish.yml` | un tag `X.Y.Z` | `test` (3.10 – 3.14) et `ci-green` → `build` → `publish` (PyPI) → `github-release` | lecture ; `ci-green` lit les Actions, `publish` demande `id-token: write`, `github-release` demande `contents: write` |

- **Droits** : chaque workflow déclare `contents: read` ; seuls les deux jobs
  ci-dessus demandent davantage. Le réglage par défaut du dépôt est aussi en
  lecture.
- **Délais** : chaque job en a un, de 10 à 45 minutes — largement au-dessus du
  run le plus long mesuré (10 minutes, pour les mutations).
- **Concurrence** : un push plus récent sur la même référence annule les runs
  `tests` et `integration` plus anciens ; deux publications ne tournent jamais
  en même temps et aucune n'est annulée.
- **Jeton sur le disque** : aucun checkout ne le laisse dans `.git/config`
  (`persist-credentials: false`).
- **Scripts** : aucune expression `${{ … }}` n'est développée dans un script
  `run:` ; les valeurs passent au shell par l'environnement.
- **Échecs** : aucun n'est masqué — pas de `continue-on-error`, pas de
  `|| true`. Le seul `if: failure()` téléverse le journal d'audit d'un job en
  échec ; les blocs `set +e` capturent un code de sortie vérifié à la ligne
  suivante.
- **Cache** : aucun. Aucun workflow n'en déclare, et le cache d'image de
  l'action QEMU est désactivé (`cache-image: false`).

## La publication

Une version se publie en poussant un tag. Rien d'autre ne peut publier.

1. **Tests**, sur les cinq versions de Python — et **CI verte sur le commit
   tagué** (`ci-green`) : les workflows `Tests` et `Integration` doivent avoir
   réussi sur ce commit précis, poussé sur `main`, sinon rien n'est construit.
   Un run rouge arrête la publication ; un run en cours est attendu (jusqu'à
   une heure) ; un commit jamais poussé sur `main` est refusé. Ce qui compte
   comme réussi : pour chaque workflow, identifié par son fichier, le run le plus
   récent du SHA tagué exact poussé sur `main`, dans l'état de sa dernière
   tentative, est `completed` et `success`. Le job n'a que `actions: read`.
   Mesuré avec l'API GitHub : le commit de la 0.28.1 vert, un commit aux tests
   en échec refusé, un commit présent seulement sur une branche Dependabot
   refusé, un run en échec puis réussi à sa seconde tentative compté réussi.
2. **Build**, sur Python 3.12 :
   - pip est installé depuis une roue épinglée par son SHA-256 (26.2.2, le
     premier pip qui ne fait plus confiance aux autorités eMudhra / emSign), et
     le job en refuse une plus ancienne ;
   - le tag doit être un `MAJEUR.MINEUR.CORRECTIF` nu égal à la version de
     `pyproject.toml`, sinon rien n'est construit — **c'est** le contrôle
     strict du tag ;
   - les outils de build viennent de `requirements-ci.txt`, chacun épinglé par
     version et SHA-256 (`pip install --require-hashes`) ;
   - `python -m build` installe son backend dans un environnement isolé : cet
     environnement reçoit `requirements-build.txt` (setuptools épinglé par
     SHA-256) par `PIP_CONSTRAINT`. Le job `build-backend-pin` de `tests.yml`
     prouve à chaque push que la contrainte mord : le même build aux
     empreintes remplacées — et rien d'autre, ce que le job vérifie — doit
     échouer, et échouer sur la vérification d'empreinte.
3. **PyPI**, par Trusted Publishing (OIDC) : aucun jeton PyPI n'existe.
   - Le job tourne dans l'environnement `release`, qui attend l'approbation du
     mainteneur (les administrateurs ne peuvent pas la contourner). Son filtre
     de tags, `[0-9]*.[0-9]*.[0-9]*`, est un motif glob, pas une expression
     régulière : il laisse aussi passer `1x.2.3y`. C'est un premier filtre
     grossier ; le contrôle strict est celui de l'étape 2.
   - L'action d'envoi est épinglée par commit, mais ce qui s'exécute est le
     conteneur qu'elle lance, `ghcr.io/pypa/gh-action-pypi-publish:<commit>`,
     qu'elle tire **par tag** — lu dans le code de l'action à ce commit, et
     dans le journal de la 0.28.1 (« Unable to find image … locally », puis
     le téléchargement). Ce conteneur détient le jeton OIDC. Une étape le
     tire d'abord **par digest** et lui donne le nom que l'action demande :
     l'action le trouve et ne télécharge rien ; un test garde ce nom égal au
     commit où l'action est épinglée. L'étape échoue si l'image locale n'est
     pas ce digest, et une étape après l'envoi le revérifie : si l'action avait
     retiré le tag, le nom pointerait ailleurs.
   - Chaque fichier reçoit une attestation PEP 740 qui nomme ce dépôt,
     `publish.yml` et l'environnement `release` (vérifié sur la 0.28.1). Elle
     dit qui a construit et publié le fichier — pas que le code est sain ni
     que les tests suffisaient.
   - `skip-existing` est gardé exprès : si l'un des deux fichiers a été envoyé
     et que le job a échoué sur l'autre, une relance termine la publication au
     lieu d'échouer sur le fichier déjà présent. PyPI ne laisse jamais
     remplacer un fichier.
4. **Release GitHub**, par la CLI de GitHub sur le runner
   (`gh release create … --verify-tag`), à la place d'une action tierce qui
   détenait `contents: write` : le titre est le chapeau en gras de la ligne de
   `CHANGELOG.md`, les notes la section de la version dans
   `DOCUMENTS/CHANGELOG_FULL.md`, les fichiers construits joints. Avant le
   changement, la même commande a créé une Release brouillon avec le titre de
   la 0.28.1, ses notes octet pour octet et les deux fichiers (supprimée
   ensuite). Avant elle, une étape compare le SHA-256 de chaque fichier à
   joindre aux empreintes que PyPI publie pour la version, en attendant que PyPI
   liste **chaque** fichier attendu (jusqu'à dix minutes ; une réponse illisible
   est réessayée) : la Release porte les fichiers de PyPI, ou n'est pas créée —
   une empreinte différente, ou un fichier que PyPI liste sans que le build l'ait
   produit, est refusé ; mesuré sur la 0.28.1, un octet ajouté au sdist a été
   refusé. L'attente de chaque fichier vient de la publication
   0.28.2 : PyPI a listé la roue quelques secondes avant le sdist, le contrôle a
   pris le sdist pas encore listé pour un fichier différent et refusé la
   Release ; relancé, il est passé avec des empreintes identiques. Elle vient
   après PyPI. Si elle échoue, **ne jamais
   reconstruire** : relancer le job en échec — il télécharge le même artefact
   `dist` que l'envoi a utilisé (gardé 90 jours ; son digest est vérifié au
   téléchargement, comme le montre le journal de la 0.28.1) — ou joindre les
   fichiers téléchargés depuis PyPI, dont PyPI publie les SHA-256.

Chaque action est épinglée par commit, sa version écrite à côté. Le
30 octobre 2026, chaque commit épinglé a été comparé au tag de cette version
dans le dépôt de l'action elle-même : les six correspondaient — aucun n'est un
commit venu d'ailleurs sous le nom d'une version. Vérifié à nouveau le
31 octobre 2026 après la montée d'`actions/checkout` en 7.0.1,
d'`actions/setup-python` en 7.1.0 et de `docker/setup-qemu-action` en 4.4.0 :
les six correspondaient. Dependabot en propose les
mises à jour, une fois une version âgée d'une semaine.

## Réglages du dépôt (lus le 30 octobre 2026)

| Réglage | Valeur |
|---|---|
| Droits par défaut du jeton | lecture ; les workflows ne peuvent pas approuver de pull request |
| Actions | épinglage par commit imposé (`sha_pinning_required`) |
| Pull requests venant de forks | les nouveaux contributeurs doivent être approuvés pour lancer les workflows |
| `main` | ni force-push, ni suppression (ruleset) |
| Tags de version (`X.Y.Z`, anciens `v*`) | jamais supprimés, jamais déplacés (ruleset) |
| Environnement `release` | approbation du mainteneur, pas de contournement par un administrateur, motif glob `[0-9]*.[0-9]*.[0-9]*` |
| Secrets | aucun stocké |
| Scanner de secrets, protection au push | actifs |
| Alertes de vulnérabilités Dependabot | actives — elles couvrent les outils épinglés dans `requirements-*.txt` |

## Pull requests et code d'autrui

- `tests.yml` et `integration.yml` tournent sur `pull_request`, jamais
  `pull_request_target` : une pull request tourne avec un jeton en lecture
  seule et sans aucun secret, sur un runner que GitHub jette après le job. Le
  run d'un nouveau contributeur attend une approbation.
- Publier demande un tag ; un fork ne peut pas en pousser ici.
- Le job arm64 lance des conteneurs privilégiés : seule l'image QEMU
  (`tonistiigi/binfmt`, épinglée par digest) tourne avec `--privileged`, pour
  enregistrer l'émulateur dans le noyau du runner — lu dans le code de
  l'action. Le code testé tourne dans un `docker run` séparé, sans privilège.

## Les distributions que la CI fait tourner

Debian 12 et 13, Ubuntu 22.04, 24.04 et 26.04, Fedora 44, openSUSE Leap 16,
Alpine 3.24, Kali Rolling, et Debian 12 en arm64 sous QEMU. Dans chacune, pip
26.2.2 est installé par empreinte dans un venv neuf (le pip de la distribution
peut être plus ancien — celui d'openSUSE Leap 16 était en 26.1.2), setuptools
est installé par empreinte, et BOB est construit avec lui en roue ; puis un
audit hors ligne et un plugin dans le bac à sable. Le job échoue sur un code de
sortie supérieur à 3, une clé de traduction affichée brute ou une trace d'erreur
Python. Les étapes appellent le venv par son chemin absolu, jamais par
`GITHUB_PATH` : le runner construit le `PATH` d'une étape de conteneur à partir
de celui que déclare l'image, et `opensuse/leap:16.0` n'en déclare aucun — avec
le venv ajouté, l'étape suivante ne trouvait plus `sh` (trouvé au premier push
de la 0.28.2).

La règle : seulement des versions encore supportées — la ligne LTS ou stable là
où la distribution en a une (Ubuntu, Debian, openSUSE Leap), la version du
Tier 1 là où elle n'en a pas (Fedora, Alpine). La fin de support de chaque image
est notée dans `tests/test_v0282_ci_hardening.py` ; passé cette date, la suite
échoue jusqu'à ce que l'image soit remplacée. Kali Rolling n'a pas de date de
fin : elle porte à la place la date de sa dernière revue complète (le
30 octobre 2026), et la suite échoue six mois après tant que la revue n'est pas
refaite. La 0.28.2 a remplacé Ubuntu 25.04 (fin le 17 janvier
2026) et Fedora 41 (le 15 décembre 2025), et ajouté Alpine et openSUSE ; chaque
image a d'abord passé toutes les étapes dans podman, arm64 compris.

## Ce qui n'est pas couvert

- **Les images sur lesquelles la CI teste** sont prises par tag (`debian:13`,
  `alpine:3.24`…), pas par digest. C'est un choix, pas un oubli : un tag suit
  les mises à jour de sécurité de chaque distribution, un digest les figerait ;
  le prix est que deux runs à des jours différents peuvent ne pas utiliser la
  même image. Ce sont les 9 constats que zizmor relève encore — des constats
  d'analyse statique, pas des vulnérabilités. L'image QEMU, qui tourne en mode
  privilégié, et le conteneur d'envoi, qui détient le jeton PyPI, sont
  épinglés par digest.
- **Le runner lui-même** — son image (`ubuntu-latest`), son Python, son
  système — est celui de GitHub ; les épinglages fixent le backend et les
  outils, pas tout l'environnement.
- **Les dépendances propres aux actions** : épingler une action par commit fixe
  son code ; une image ou un outil que l'action récupère à l'exécution n'est
  fixé que là où ce dépôt le fait (l'image QEMU, le conteneur d'envoi).
- **Dependabot** propose les mises à jour des actions, pas celles des outils
  Python épinglés : ceux-ci se régénèrent avec `scripts/gen_ci_requirements.py`,
  et une vulnérabilité dans l'un d'eux déclenche une alerte.
- **`main` n'a pas de vérification de statut obligatoire** : un commit arrive
  sur `main` avant que sa CI tourne (le projet vit sur une seule branche). Une
  *publication*, elle, est verrouillée : `ci-green` refuse un tag dont le commit
  n'est pas vert.
- **Les réglages du dépôt** ne sont pas lisibles par le jeton des workflows
  (ils demandent des droits d'administration) : ils sont vérifiés par
  `scripts/check_repo_settings.py`, lancé avec la session `gh` du mainteneur
  avant un push qui mène à une version, pas par la CI.

## Pour que ça le reste

- Régénérer les outils épinglés : `python3 scripts/gen_ci_requirements.py`
  (écrit `requirements-ci.txt` et `requirements-build.txt` depuis les versions
  listées dans le script).
- Une mise à jour d'action arrive comme pull request Dependabot ; elle garde
  l'épinglage par commit. Pour `pypa/gh-action-pypi-publish`, le test échoue
  tant que l'étape de pré-tirage ne nomme pas le nouveau commit ; son digest
  se relit alors sur ghcr.io pour ce tag (le test vérifie le commit, pas le
  digest).
- Remplacer une distribution avant sa fin de support, et noter la nouvelle date
  dans le test ; repasser Kali par toutes les étapes tous les six mois et mettre
  sa date à jour.
- Avant un push qui mène à une version : `python3 scripts/check_repo_settings.py`
  (13 réglages lus par l'API ; il dit lequel a changé).

Les gardes : `tests/test_v0270_release_chain_pins.py`,
`tests/test_v0281_build_backend_pinned.py`,
`tests/test_v0282_ci_hardening.py`, `tests/test_v0280_ci_apt_step.py` — chacune
avec des mutations qui ramènent son défaut.

---
© 2026 Cédric Clauzel
