*[Read in English](AUTOMATION.md)*

# Automatisation — BOB

Ce document explique comment configurer BOB pour s'exécuter automatiquement selon un planning et vous notifier en cas de problème.

---

## Configuration rapide

```bash
sudo bob --install-cron
```

Le wizard vous guide en 7 étapes :

1. **Nom** — un court libellé pour ce cron (ex : `nightly`, `weekly`). Appuyez sur Entrée pour utiliser le nom suggéré.
2. **Planification** — choisissez parmi :
   - Tous les jours
   - Certains jours de la semaine (ex : `1 3 5` pour Lun/Mer/Ven)
   - Certains jours du mois (ex : `1 15` pour le 1er et le 15)
   - Expression cron personnalisée (ex : `0 3 * * 1`)
3. **Heure** — heure d'exécution au format `HH:MM` (défaut : `03:00`). Non affichée pour les expressions personnalisées.
4. **Email** — adresse(s) de notification facultative(s) : choisissez-en dans le carnet d'adresses, saisissez-en une nouvelle, ou `0` pour aucune (voir *Plusieurs emails de notification* plus bas).
5. **Profil** — `server`, `desktop`, `workstation` ou `container`.
6. **Langue** — anglais ou français, pour le rapport comme pour l'e-mail de notification.
7. **Sondes sortantes** — actives, ou désactivées (`--offline`).

Un aperçu en langage naturel est affiché avant confirmation :
```
  → Planification : tous les lundi, mercredi, vendredi à 02:30
```

`y` l'applique et `Échap` revient en arrière ; depuis la v0.39.0, aucune autre touche n'y fait rien (`Entrée` l'appliquait, toute autre touche l'abandonnait, sans que rien ne l'annonce). Quand une tâche de ce nom existe déjà, l'assistant demande avant de l'écraser, dans la formulation de toute confirmation : *Appuyez sur y pour confirmer, sur toute autre touche pour annuler* — un refus revient en arrière.

### Ce que l'audit programmé exécute réellement

Les étapes 5 à 7 existent parce qu'**un cron s'exécute en root**. Avant la
v0.16.1, le script généré lançait un `bob --quiet --detailed` figé : l'audit
programmé lisait donc le profil enregistré de *root* — pas le vôtre — et
l'environnement nu de cron, où `$LANG` est généralement absent, si bien que le
rapport sortait en anglais quel que soit votre choix.

Ce n'était pas qu'une question de cosmétique : le profil décide quels constats
déduisent, donc le nombre d'avertissements, donc le code de sortie, donc si
l'e-mail de notification part ou non.

Chacun des trois écrans s'ouvre sur la valeur donnée à la commande qui
installe le cron — son `-p`, sa langue (`--french` / `--lang`, sinon le `$LANG`
détecté) et son `--offline` : `sudo bob -p desktop --french --install-cron` ne
demande que trois touches. Sans `-p`, l'écran du profil s'ouvre sur votre profil
enregistré (depuis la 0.25.1 ; il s'ouvrait sur `server` avant), sinon sur `server`. La ligne de commande résultante est affichée avant toute écriture :

```
  Commande programmée : bob --quiet --detailed --profile desktop --french
```

`--quiet` et `--detailed` sont structurels, pas des préférences : cron n'a pas
de terminal, et l'e-mail de notification *est* le `.log` qu'écrit `--detailed`.
Depuis la v0.18.0, ce fichier porte l'explication, la commande et la clé de
chaque constat. Auparavant, le chemin `--quiet` n'écrivait qu'un niveau et un
message : un rapport planifié nommait chaque problème et aucune des corrections
que le même audit affichait dans un terminal.

Une mise à jour ne touche pas les crons existants — leur script conserve la
ligne de commande avec laquelle il a été généré. Relancez
`sudo bob --install-cron` avec le même nom pour en régénérer un.

### Hôtes sans `/etc/cron.d`

BOB écrit ses tâches dans `/etc/cron.d`, le répertoire que lisent cronie, cron et les dérivés de Vixie-cron. BusyBox crond (Alpine) lit un fichier par utilisateur dans `/etc/crontabs/` et n'a pas de `/etc/cron.d`. Depuis la 0.26.0, une tâche y est un bloc de la crontab de root, `/etc/crontabs/root`, entre deux lignes de repère :

```
# BEGIN BOB cron bob-NOM
# BOB cron — generated AAAA-MM-JJ by bob --install-cron
# name: NOM
# email: 
0 3 * * *  /usr/local/bin/bob-NOM
# END BOB cron bob-NOM
```

Seul ce bloc est réécrit — par `--manage-cron` (horaire, e-mail) et à la suppression ; les lignes que le système ou vous avez mises dans la crontab restent telles quelles. Chaque modification se termine par l'écriture de `root` dans `/etc/crontabs/cron.update`, ce qui fait relire le fichier à BusyBox crond (mesuré sur Alpine 3.24 : sans lui, une modification n'était pas prise en compte en trois minutes ; avec lui, en moins d'une minute). La 0.25.1 refusait l'assistant sur un tel hôte.

### Fichiers créés

- `/usr/local/bin/bob-{nom}` — script wrapper
- `/etc/cron.d/bob-{nom}` — entrée cron système (BusyBox crond : un bloc `# BEGIN/END BOB cron bob-{nom}` de `/etc/crontabs/root` à la place)

---

## Gestion des crons

```bash
sudo bob --manage-cron
```

Liste tous les crons installés avec leur planning et leur email de notification.
Dans un terminal, c'est un écran curses (les touches communes ci-dessous, plus
`Entrée` pour modifier un cron, `Espace` / `a` pour en marquer un ou tous, `d`
pour supprimer des crons par leurs numéros — la saisie part des marqués, sinon
de celui sous le curseur, et prend `3`, `1,3`, `2-5` ou `all` (CONVENTIONS.md) —
`m` pour le carnet d'adresses, `l` pour la langue
et `q` pour quitter) ; quand stdout n'est pas un terminal, c'est le menu texte
ci-dessous. Les deux bouclent jusqu'à ce que vous quittiez :

```
  1. nightly              tous les jours à 03:00
     → email: vous@exemple.com
  2. weekly-monday        tous les lundi à 02:00

  Gérer vos crons :

    1        modifier le cron n°1
    e:1      modifier l'email de notification du cron n°1
    d:1      supprimer le cron n°1
    d:1,3    supprimer les crons n°1 et n°3
    d:1-3    supprimer les crons n°1 à n°3
    d:all    supprimer tous les crons
    m        gérer le carnet d'adresses email

  Entrée ou 'q' pour quitter.
  >
```

| Commande | Action |
|----------|--------|
| `N` | Modifier le cron N — choisir entre planning ou email de notification |
| `e:N` | Modifier directement l'email de notification du cron N |
| `d:N` | Supprimer le cron N et son script associé |
| `d:1,3` | Supprimer les crons 1 et 3 (liste) |
| `d:1-3` | Supprimer les crons 1 à 3 (plage) |
| `d:all` | Supprimer tous les crons installés |
| `m` | Ouvrir le carnet d'adresses email (voir ci-dessous) |
| Entrée / `q` | Quitter |

Après chaque action, le menu se réaffiche pour enchaîner plusieurs opérations.

---

## Supprimer un cron

Dans le menu texte, entrez `d:N` pour supprimer un cron, ou utilisez liste, plage ou `all` pour une suppression en lot :

```
  > d:1
  Supprimer le cron 'nightly' ? [y/N] y
  ✔ Cron 'nightly' supprimé

  > d:1,2
  Supprimer 2 crons (nightly, weekly) ? [y/N] y
  ✔ 2 crons supprimés

  > d:all
  Supprimer TOUS les 2 crons ? [y/N] y
  ✔ 2 crons supprimés
```

---

## Carnet d'adresses email

Le carnet d'adresses (`m`) permet de gérer les adresses de notification enregistrées indépendamment des crons. Il est accessible même sans cron installé :

```
  ╔════════════════════════════════════════════════════════════╗
  ║  CARNET D'ADRESSES EMAIL                                   ║
  ╚════════════════════════════════════════════════════════════╝

  1. vous@exemple.com
  2. admin@exemple.com

  Gérer vos adresses email enregistrées :

    1        supprimer l'adresse n°1
    1,3      supprimer les adresses n°1 et n°3
    1-3      supprimer les adresses n°1 à n°3
    all      supprimer toutes les adresses
    a        ajouter une nouvelle adresse

  Entrée ou 'q' pour quitter.
  >
```

Dans un terminal, le carnet est lui aussi un écran curses : `Espace` / `a` marquent une adresse ou toutes, `n` en ajoute une, `d` supprime des adresses par leurs numéros (la saisie part des marquées, sinon de celle sous le curseur ; `3`, `1,3`, `2-5` ou `all`), `Échap` revient en arrière. Depuis la v0.39.0, les adresses et les crons sont numérotés, et toute suppression est confirmée.

| Commande | Action |
|----------|--------|
| `a` | Ajouter une nouvelle adresse validée |
| `N` | Supprimer l'adresse N |
| `1,3` | Supprimer les adresses 1 et 3 |
| `1-3` | Supprimer les adresses 1, 2 et 3 |
| `all` | Supprimer toutes les adresses enregistrées |

Depuis la v0.39.0, toute suppression demande d'abord (`[y/N]` ; elle supprimait sans rien demander), et les numéros suivent la règle de toute liste de numéros de BOB (CONVENTIONS.md) : un intervalle prend les adresses qui existent entre ses bornes, un numéro donné seul — isolé ou dans une liste — doit être une adresse, sinon rien n'est supprimé et ce numéro est dit ; les formes se mélangent (`1,3-5`).

| Entrée / `q` | Revenir au menu de gestion des crons |

Les adresses enregistrées ici sont proposées comme suggestions à chaque fois que `--install-cron` ou `--manage-cron` demande un email de notification.

---

## Plusieurs emails de notification 

`--install-cron` supporte plusieurs destinataires. Après chaque sélection, il vous est demandé si vous souhaitez en ajouter un autre :

```
  Email(s) de notification :
    → Sélectionnés jusqu'ici : admin@exemple.com
    0. (aucun / terminer)
    1. admin@exemple.com ✔
    2. securite@exemple.com
    3. Saisir une nouvelle adresse...
  > 2
  Ajouter une autre adresse email ? [o/N] n
```

Toutes les adresses sélectionnées sont stockées séparées par des virgules et chacune reçoit un email individuel lorsque l'audit détecte des problèmes.

> **Note Postfix :** Aucune configuration supplémentaire n'est nécessaire pour plusieurs destinataires. Postfix envoie toujours depuis le compte unique configuré dans `sasl_passwd` (l'expéditeur). Les destinataires peuvent être n'importe quelle adresse email valide — sur le même domaine ou des domaines différents — sans configuration additionnelle.

---

## Prérequis pour l'email

Les notifications nécessitent `sendmail` — fourni par tout MTA standard :

```bash
# MTA local (recommandé pour les serveurs) :
sudo apt install postfix

# MTA relais uniquement (pour desktops relayant via Gmail, Outlook, etc.) :
sudo apt install msmtp-mta
```

Les commandes ci-dessus sont celles de Debian. `postfix` et `msmtp` portent le
même nom de paquet sur la plupart des distributions ; le paquet compagnon
`-mta`, qui installe le binaire `sendmail`, non — vérifiez-le auprès de votre
gestionnaire de paquets.

`--install-cron` détecte votre MTA (Postfix, Exim, msmtp, ssmtp) et dit lequel
il a trouvé. **Détecter n'est pas délivrer.** Tout ce qu'il établit, c'est
l'existence d'un binaire `sendmail`, ce à quoi satisfait aussi un Postfix
installé et jamais configuré, qui ne délivre pourtant rien —
voyez la configuration de relais plus bas, c'est elle qui fait réellement
sortir le courrier de l'hôte.

```bash
bob --test-email                 # envoie un vrai message par le transport du cron
```

C'est le seul moyen de savoir avant la première exécution programmée. La
commande emprunte le même chemin de code que le script cron et sort en non-zéro
quand `sendmail` refuse le message. Une sortie zéro signifie que le MTA l'a
*accepté* — un relais ou un filtre anti-spam peut encore le jeter, vérifiez donc
la boîte de réception une fois.

La notification est envoyée **uniquement quand l'audit sort en non-zéro** — avertissements, alertes, erreur technique ou `--target` manqué. Si votre configuration est saine, vous ne recevez rien : le silence seul ne prouve donc pas que la route du mail fonctionne, c'est le rôle de `bob --test-email`.

---

## Format des fichiers cron

Chaque fichier cron inclut des métadonnées en commentaires pour l'identification. Les emails multiples sont stockés séparés par des virgules :

```
# BOB cron — generated 2026-10-16 by bob --install-cron
# name: nightly
# email: admin@exemple.com,securite@exemple.com
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

0 3 * * *  root  /usr/local/bin/bob-nightly
```

---

## Webhooks

En complément (ou à la place) des notifications email, BOB peut POSTer le résumé d'audit vers une URL webhook. Deux formats supportés : payload compatible Slack et enveloppe JSON générique.

```bash
sudo bob --webhook https://hooks.slack.com/services/T00.../B00.../XX...
sudo bob --webhook https://mon-endpoint-interne.exemple.com/audit
```

### Détection automatique du format

BOB inspecte l'URL pour choisir le format de payload :

| Pattern d'URL | Format de payload |
|---------------|-------------------|
| `hooks.slack.com/services/...` | Slack (attachment riche avec blocs color-coded) |
| autre | Enveloppe JSON générique |

Forcer un format spécifique avec `--webhook-format` :

```bash
sudo bob --webhook URL --webhook-format=slack    # force format Slack
sudo bob --webhook URL --webhook-format=generic  # force JSON générique
```

### Payload Slack

Le message Slack inclut :

- Une ligne de synthèse : version de BOB, hôte, score, écart au durcissement (champ `risk`), et nombre d'alertes et d'avertissements
- La liste des constats ALERT et WARN, chacun avec son détail, coupée à 2500 caractères (une ellipse marque la coupe)
- Une pièce jointe colorée : rouge s'il y a une alerte, orange s'il n'y a que des avertissements, vert sinon

Il ne porte aucun score par domaine, et son score est le nombre brut — il n'affiche pas le `≤` d'un score qui n'est qu'un plafond ; l'enveloppe générique ci-dessous a les champs qui le disent.

### Enveloppe JSON générique

Le payload générique est volontairement minimal et stable :

```json
{
  "source": "bob",
  "version": "0.25.0",
  "host": "example.local",
  "timestamp": "2026-06-11T18:42:01+00:00",
  "score": 8,
  "score_is_upper_bound": false,
  "score_low": 8,
  "score_high": 8,
  "unscored_domains": [],
  "unverified": [],
  "max_score": 10,
  "risk": "low",
  "alerts": 1,
  "warnings": 2,
  "profile": "server",
  "degraded_sections": [],
  "domain_scores": {"firewall_network": 10, "exposure_services": 9, "access_control": 7, "system_hardening": 8, "health_resilience": 9, "detection": 8},
  "findings": [
    {"level": "ALERT", "key": "ssh.permit_root_login", "message": "Connexion root autorisée via SSH", "qualified_by": [], "detail": "", "note": ""}
  ]
}
```

Cette enveloppe générique a son **propre** contrat plat (distinct du schéma d'audit `bob --json`) : clés top-level `source`/`max_score`/`timestamp` et une map plate `domain_scores` de `{domaine: score}` sur les six clés de domaine. `alerts` et `warnings` sont des **compteurs (entiers)** ; le tableau `findings` énumère toujours les constats de niveau ALERT et WARN (chacun avec `level`/`key`/`message`/`qualified_by`/`detail`/`note`). `risk` est le niveau **effectif** (avec escalade de posture), en minuscules (`"low"` / `"medium"` / `"high"` / `"critical"`). Note : le webhook garde les noms `alerts`/`warnings` — seul le schéma d'audit `bob --json` les a renommés en `alert_count`/`warning_count` en v0.12.0 (F9).

**Champs ajoutés depuis la v0.14.1**, tous additifs — les récepteurs existants ne sont pas affectés :

  - **`profile`** — le profil d'audit qui a produit ces chiffres. Depuis la v0.14.0 le profil change les sévérités des constats, `warnings` et donc le code de sortie : deux payloads du même hôte peuvent légitimement diverger, et sans ce champ rien ne l'explique. À utiliser pour regrouper ou comparer des hôtes.
  - **`degraded_sections`** — les sections dont le check a levé une exception et qui ont été dégradées sur place au lieu d'interrompre l'audit (liste vide sur une exécution saine). **C'est le champ sur lequel alerter.** Un récepteur voyant `score: 9, alerts: 0` ne peut pas distinguer autrement un hôte sain d'un hôte où deux sections n'ont jamais tourné ; le code de sortie reste délibérément piloté par les constats réels (sauf avec `--target`), donc un récepteur voit l'incomplétude ici — les constats INFO `<section>.unavailable` ne figurent pas dans l'enveloppe, qui ne porte que les ALERT et WARN.
  - **`score_is_upper_bound`** — vrai quand un check n'a pas pu lire son entrée. Les déductions qu'il n'a pas faites sont **inconnues, pas nulles**, donc `score` est un plafond. Un audit lancé sans les privilèges nécessaires affiche un score *plus élevé* qu'un audit complet : une règle de supervision portant sur `score` seul peut donc passer au vert sur une exécution plus aveugle. **`unverified`** liste les clés de constat qui l'expliquent, et (v0.16.2) `score_low` / `score_high` encadrent le vrai score tandis que `unscored_domains` nomme les domaines que l'aveuglement a retirés de la moyenne. Depuis la v0.16.0, `--target N` échoue aussi fermé sur un score borné : un portail ne peut pas être satisfait par un plafond.

Une règle de supervision raisonnable est donc « alerter sur `alerts > 0`, et avertir séparément dès que `degraded_sections` est non vide » — la seconde condition signifie que c'est l'audit lui-même qui est en mauvaise santé, pas l'hôte.

### Comportement

- Le webhook est POSTé **à chaque exécution dès qu'une URL webhook est configurée** (flag CLI ou `webhook_url` dans la config). Ce n'est *pas* conditionnel à la présence d'alertes/avertissements — voir `bob/__main__.py` `if _webhook_url and not config.offline:`. Un audit clean déclenche toujours une livraison ; filtrer côté récepteur en inspectant `alerts`/`warnings`/`score`.
- `--offline` (ou `-o`) désactive complètement la livraison webhook. À utiliser pour les sandboxes de build distro et environnements air-gapped.
- Un POST webhook échoué **n'affecte pas** le code de sortie de l'audit — c'est une notification best-effort, pas un gate. Les erreurs sont écrites sur stderr.
- Chaque URL webhook est appelée avec un **timeout de 10 secondes** (`bob.webhook._TIMEOUT_SECONDS = 10`).

### Combinaison avec cron

Le script wrapper cron généré par `--install-cron` n'inclut pas de flag `--webhook`. Un audit programmé tourne en root et déclenche le webhook enregistré dans la configuration de **root** (`/root/.config/bob/config.conf`) ; `sudo bob --webhook=URL` ne l'y met pas — sous `sudo`, BOB enregistre l'URL dans la configuration de l'utilisateur qui l'a lancé. Le moyen direct est d'éditer le wrapper généré à `/usr/local/bin/bob-{name}` et d'ajouter le flag à l'invocation `bob` :

```bash
sudo nano /usr/local/bin/bob-nightly
# remplacer :  /usr/local/bin/bob --quiet --detailed --profile server --english
# par :        /usr/local/bin/bob --quiet --detailed --profile server --english --webhook https://hooks.slack.com/...
```

Relancer `--install-cron` avec le même nom régénère le script et efface la modification.

---

## Surveillance et suivi

Au-delà des audits planifiés, BOB propose une poignée de flags qui aident les opérateurs à observer l'état du système dans le temps. Ce ne sont pas des "automatisations" au sens cron, mais elles s'intègrent dans la même boîte à outils opérationnelle.

### `--watch=N` — mode surveillance en direct

Relance l'audit toutes les `N` secondes jusqu'à interruption avec `Ctrl-C` :

```bash
sudo bob --watch=60
```

Chaque passe affiche une ligne — heure, score, barre de score et écart au durcissement — puis *Aucun changement détecté depuis le dernier audit* ou les constats apparus ou résolus depuis la passe précédente, puis l'heure de la passe suivante ; la première passe ne fait que fixer le point de comparaison. La sortie défile ; rien n'est redessiné sur place. L'intervalle est d'au moins 10 s. Cas d'usage :

- Observer un changement de durcissement prendre effet (`sudo sysctl -w ...` → la passe suivante voit le WARN disparaître)
- Démontrer l'audit en live en réunion
- Vérifier un changement fail2ban / pare-feu sans relancer manuellement

`--watch` est incompatible avec `--json`, `--output=csv`, `--output=markdown` et `--html` (utilise la sortie terminal interactive).

### `--diff` — afficher uniquement ce qui a changé

Compare l'audit courant au précédent et n'affiche que le delta :

```bash
sudo bob --diff
```

Après les lignes de score et de compteurs, une ligne par clé ALERT/WARN apparue ou résolue — ou qui n'a pas pu être comparée parce que sa section n'a pas été lue cette fois (*Non réévalué*) :

```
⚠ [ATTENTION] Nouveau constat : clamav.scan_old
✔ [OK] Résolu : hardening.send_redirects_enabled
✔ [OK] Résolu : ssh.x11.forwarding.server
```

Le fichier baseline vit à `~/.config/bob/last_baseline.json` (mode `0600`) et est réécrit à la fin de chaque audit complet. Un fichier passé à `--diff` qui ne porte ni `timestamp` ni `score` est refusé comme *n'étant pas une baseline BOB* (code 3) au lieu d'être comparé comme une baseline à zéro. Pour effacer la baseline et repartir à zéro :

```bash
sudo bob --reset-baseline
```

### `--history` — tendance du score dans le temps

Affiche un sparkline sur les 50 derniers scores d'audit depuis
`~/.config/bob/history.jsonl`, puis une table des dix plus récents avec leur
flèche de tendance :

```bash
bob --history
```

```
  Historique des scores
  ────────────────────────────────────────────
  ▅▅▆▆▇▇▇▇

  2026-05-17 00:00   8/10  →  low
  2026-05-16 00:00   8/10  →  low
  2026-05-15 00:00   8/10  ↑  low
  2026-05-14 00:00   7/10  →  medium
  2026-05-13 00:00   7/10  ↑  medium
  2026-05-12 00:00   6/10  →  medium
```

Le sparkline couvre jusqu'à 50 entrées ; la table en dessous en liste 10.

Le fichier d'historique append une ligne par audit (timestamp + score + niveau) et rotate à 1000 entrées. Une ligne dont le score ou l'horodatage est illisible est ignorée plutôt que réparée : un fichier abîmé raccourcit le tableau au lieu de dessiner une tendance qui n'a jamais eu lieu. Pas de sudo requis pour `--history` seul.

### `--breakdown` (`-B`) — transparence du calcul de score

Affiche le calcul complet du score après le résumé d'audit : chaque déduction, chaque plafond, et les scores bruts par domaine avant moyennage.

```bash
sudo bob --breakdown
sudo bob -B                       # forme courte
```

À utiliser quand le score affiché ne correspond pas à votre intuition et que vous voulez savoir *quelles* déductions s'y sont additionnées. La sortie est lisible mais assez verbeuse — typiquement utilisé une fois après un changement de config plutôt qu'en audit de routine.

---

## Périmètres d'équipe

*Depuis la 0.43.0.* Plusieurs personnes utilisent BOB sur le même hôte, avec
des niveaux de confiance différents. Le chef d'équipe — le **maître** —
déclare ce que chaque compte est censé faire avec BOB. **BOB n'empêche rien** :
une action hors du périmètre déclaré du compte qui la lance est annoncée,
redemandée, et inscrite au journal d'équipe, qu'elle soit ensuite faite ou
abandonnée. BOB mesure un écart à une déclaration ; il ne juge pas une faute.
Ce qu'un compte peut réellement faire reste l'affaire de Linux (comptes,
groupes, sudoers).

Sans déclaration, rien ne change : aucune question, aucun journal, aucune ligne.

### Déclarer l'équipe

```bash
sudo bob --team init                          # votre compte de session devient le maître
sudo bob --team grant carol audit,note,fix:firewall_network
sudo bob --team grant dave audit
sudo bob --team revoke carol fix:firewall_network
sudo bob --team remove dave
bob --team                                    # la déclaration, et votre propre périmètre
sudo bob --manage-team                        # la même chose, sur un écran plein
```

`--manage-team` est un écran plein comme `--manage-logs` : l'équipe (le
maître, les attributs de chaque membre en cases à cocher — Espace coche,
Entrée applique ; `n` ajoute un compte, `d` en retire un) et ce qui est
enregistré ; les journaux se lisent dans `--manage-logs`, troisième choix de
l'accueil. Chaque changement appelle le même code que les
commandes, avec les mêmes contrôles, les mêmes traces, et la même question
hors d'un périmètre déclaré — posée sur l'écran. Sans terminal (un tube, un
script), il propose la même chose sous forme de menu numéroté.

La déclaration est dans `/etc/bob/team.conf` (à root, `0644` : chacun peut lire
son périmètre) et seul BOB l'écrit. Chaque écriture est inscrite au journal
d'équipe avec l'empreinte du fichier ; une déclaration modifiée à la main est
signalée à chaque action, inscrite une fois au journal, et reste appliquée.

| Attribut | Couvre |
|---|---|
| `audit` | tout audit, y compris `--exhaustive`, `--watch`, `--diff` |
| `fix:<domaine>` | les commandes de `--fix --apply` qui répondent à un constat de ce domaine de score (`firewall_network`, `exposure_services`, `access_control`, `system_hardening`, `health_resilience`, `detection`) ; `fix:*` pour tous |
| `note` | ajouter une note, modifier ou retirer ses propres notes (`--manage-logs`) |
| `note-autres` | modifier ou retirer les notes d'un autre compte ; purger des notes |
| `purge` | supprimer des rapports (`--manage-logs`), `--reset-baseline` |
| `config` | `--ignore`, `--unignore`, `--reconfigure`, `--install-cron`, `--manage-cron`, `--test-email`, `--test-webhook`, `--install-completion` |
| `equipe` | `--team grant`, `revoke`, `remove` |

Le maître a tous les attributs. Lire (`--help`, `--explain`, `--history`,
`--fix-journal`, `--team`, les vues de `--manage-logs`) n'en demande aucun.

### Qui agit

Le compte que BOB nomme est celui que donne le login uid du noyau — la session
qui a lancé `sudo`, pas root. Une connexion directe en root est un compte comme
un autre : non déclaré, toutes ses actions sont hors périmètre. Sans session
(cron, service), l'action n'est **pas attribuée** : faite, et inscrite comme
telle.

### Hors du périmètre déclaré

```
⚠ une commande de --fix --apply : hors du périmètre déclaré pour dave — il ne
  comprend pas « fix:detection ». Si elle est faite, elle est inscrite au
  journal d'équipe comme hors du périmètre déclaré (maître : alice).
  La faire quand même ? [y/N]
```

- **y** : faite, inscrite *confirmée* ; **toute autre réponse** : non faite,
  inscrite *abandonnée*.
- `-y` ne répond pas à cette question : avec `--fix --apply -y`, chaque
  commande hors périmètre est quand même demandée.
- Sans terminal pour demander (un script), l'action est faite et inscrite
  *non confirmée*.
- La question part sur stderr : une sortie `--json` reste propre.

### Les journaux : ce qui a été fait, quel que soit l'auteur

Pour le suivi, une action laisse une trace **quel que soit l'auteur, maître
compris** — « hors du périmètre déclaré » s'y ajoute. Un journal par domaine,
tenu même sans équipe :

| Journal | Contient |
|---|---|
| `team` | les changements de la déclaration, les tentatives hors d'un périmètre déclaré, les actions sans session, une déclaration modifiée hors de BOB |
| `cron` | les audits planifiés créés, modifiés (horaire, adresses), supprimés ; les adresses ajoutées au carnet ou retirées |
| `admin` | `--ignore`, `--unignore`, `--reconfigure`, `--reset-baseline`, `--test-email`, `--test-webhook`, `--install-completion` quand ils réussissent ; les rapports supprimés dans `--manage-logs` ; chaque changement de ce qui est enregistré |

```bash
sudo bob --journals                       # ce qui est enregistré, la chaîne de chaque journal
sudo bob --journals show cron             # un journal (code 0 intact, 2 rompu, 4 illisible)
sudo bob --journals off rapports          # ne plus enregistrer les suppressions de rapports
sudo bob --team-journal                   # = --journals show team
```

Ce qui peut être coupé : `cron`, `carnet` (carnet d'adresses), `config`,
`rapports`. **Jamais** : le journal d'équipe, et les changements de ce réglage
— couper un journal est lui-même inscrit au journal d'administration, cela ne
peut donc pas se faire en silence. Seul le maître le règle (`equipe`) ; tout
autre compte est questionné et marqué, comme pour toute action hors de son
périmètre. Un fichier de réglage (`/etc/bob/journals.conf`) modifié à la main
est signalé, inscrit une fois, et reste appliqué ; un fichier illisible ne
coupe rien.

Chaque journal (`/var/log/bob/<nom>.journal`) est tenu comme le journal de
`--fix --apply` ([FIX_JOURNAL_FR.md](FIX_JOURNAL_FR.md)) : à root, `0640`
groupe adm, chaque ligne chaînée à la précédente, en ajout seul quand le
système de fichiers le permet, chaque ligne aussi envoyée au journal système
(`bob-team`, `bob-cron`, `bob-admin`). Une ligne modifiée se voit à la
suivante ; la dernière, c'est le témoin du journal système qui en répond. Dans
`--manage-logs`, le troisième choix de l'accueil les ouvre : chaque ligne se lit
« action — détails », l'action dans la couleur de son effet (vert ajoute ou
active, rouge retire, désactive ou alerte, jaune le reste) et le compte en cyan
([CONVENTIONS_FR.md](CONVENTIONS_FR.md#2-couleur--écrans-curses)) ; les sorties texte ne portent aucun code de couleur.

### Ce que BOB ne voit pas

BOB ne voit que ses propres actions : une modification de `sshd_config` à la
main, un `ufw` lancé à la main lui échappent — c'est l'affaire d'auditd. root
peut réécrire la déclaration et le journal ; la chaîne et le témoin du journal
système rendent une réécriture visible, pas impossible.

---

## Gestion des rapports

**Un plafond de taille pour les rapports** (depuis la v0.43.0). BOB ne
supprime jamais un rapport de lui-même, sauf si un plafond est fixé — utile sur
une petite machine (la carte SD d'un Pi Zero) où un audit planifié ajoute un
rapport chaque jour :

```bash
sudo bob --log-max-size=50M     # ou 500K, 2G ; off le retire (par défaut)
```

Après chaque nouveau rapport, les plus anciens du dossier où s'écrivent les
rapports sont supprimés jusqu'à repasser sous le plafond (les anciens dossiers
ne sont pas touchés) ; un rapport compte avec ses fichiers annexes (notes, état). Jamais supprimés : le rapport qu'on vient d'écrire, et un
rapport qui porte des notes (ses notes partiraient avec lui) — quand il ne reste
que ceux-là au-dessus du plafond, BOB le dit. Chaque suppression est inscrite au
journal d'administration. Fixer un plafond avertit que, trop bas, il limite la
preuve conservée, et demande confirmation. Dans `--manage-logs`, la liste des
dossiers montre le plafond et l'espace occupé, et `p` le règle.

Pour lister et supprimer les rapports générés :

```bash
sudo bob --manage-logs
```

Dans un terminal interactif, une interface TUI curses s'ouvre. Un mode texte de repli est utilisé quand stdout n'est pas un TTY (pipes, scripts).

### Mode TUI (terminal interactif)

Depuis la v0.40.0, elle s'ouvre sur **deux choix** : `1` les rapports d'audit,
`2` le journal des correctifs (`--fix --apply`), tenus à part. La ligne du
journal porte son verdict dans sa couleur — ✔ intact, ⚠ non démontré,
✖ FALSIFIÉ — et s'ouvre sur ce verdict, puis une ligne par jour, la plus récente
en haut ; `Entrée` ouvre un jour (ses commandes dans l'ordre où elles ont
tourné), puis une commande (son détail, ce que le journal système en a
enregistré, ses notes — `a` en ajoute une, en root seulement ; sans le droit,
l'écran dit comment). `r` liste les lignes retirées du journal, quand il y en a.
Ce que le journal enregistre et comment une falsification se voit, avec une
démonstration mesurée sur un vrai hôte : [FIX_JOURNAL_FR.md](FIX_JOURNAL_FR.md).
La même chose en texte, avec le verdict en code de sortie : `bob --fix-journal`.

Les rapports d'audit s'ouvrent sur un **sélecteur de dossiers** (`Échap` revient aux deux choix) : le répertoire de rapports courant et chaque répertoire antérieur que BOB suit encore, chacun avec ce qu'il contient. `Entrée` parcourt un dossier, `c` change (ou ajoute) le répertoire où vont les nouveaux rapports, `d` oublie un dossier suivi (ses fichiers sont conservés). Dans un dossier, la liste montre chaque rapport avec sa date, sa taille et son score, sous un graphique d'historique des scores.

**Le socle commun** — depuis la v0.16.3, tous les écrans curses de BOB
acceptent la même navigation, et un **bandeau orange** en bas d'écran énumère
toujours exactement ce que cet écran accepte, dans la langue de l'interface. Il
fait miroir au bandeau cyan d'en-tête et se replie sur une seconde ligne plutôt
que de tronquer quand les indications ne tiennent pas dans le terminal — couper
par la droite emporterait d'abord l'indication de sortie. La ligne juste
au-dessus est **réservée aux invites et aux messages** : une confirmation de
suppression ou un champ de saisie s'y affiche, et le bandeau de touches reste
visible en dessous au lieu d'être recouvert. Depuis la v0.39.0, le bandeau
liste **exactement** les touches que l'écran accepte — aucune touche absente du
bandeau ne fait rien, et une touche qui n'agit que dans certains états (`u`, dès
que quelque chose est marqué) n'y figure qu'alors ; un menu numéroté affiche ses
propres chiffres (`1-4 par numéro`). Toute suppression, écrasement, retrait ou
purge se confirme d'une seule façon : la question, puis *Appuyez sur y pour
confirmer, sur toute autre touche pour annuler*, au-dessus d'un bandeau qui
n'affiche que `y`. Et cette ligne prend
la couleur de ce qu'elle dit, comme la sortie texte : une **invite** ou une
question qui attend une réponse en **jaune** ; une action réussie en **vert**,
`✔` ; une action refusée ou échouée — rien n'a été changé — en **rouge**, `✖` ;
une information (une action que vous avez annulée) en **cyan**, `ℹ`. Pareil dans
tous les assistants : `--manage-logs`, `--manage-cron`, `--install-cron`,
`--explain`.

| Touche | Action |
|--------|--------|
| `↑` / `↓` ou `j` / `k` | Déplacer le curseur |
| `PgUp` / `PgDn` | Page |
| `g` / `G` | Aller au début / à la fin |
| `Entrée` | Choisir |

**Les champs de saisie.** Quand un écran demande de taper quelque chose — un
nom de tâche, une adresse e-mail, une heure — l'invite occupe la ligne réservée
et le bandeau en dessous affiche `⏎ valider` et `Esc retour` — et `Tab compléter`
là où le champ complète un chemin (un nouveau dossier de rapports). Toutes ces invites
sont traduites ; avant la v0.16.3 elles étaient en anglais dans un assistant
français.

**Les sorties.** `q` quitte, et seulement depuis la **première page** d'un
assistant — plus profond, `Échap` recule d'un écran et rien ne sort d'un coup :
une seule touche ne peut pas abandonner un cron à moitié saisi trois écrans
plus haut.

**`l` bascule la langue de l'interface**, sur les premières pages uniquement.
Cette touche existe parce que ces assistants tournent sous `sudo`, qui
réinitialise l'environnement : un opérateur dont le shell est en français peut
atterrir dans un assistant anglais sans l'avoir choisi. L'indication nomme la
langue vers laquelle on va — `l Français` en anglais, `l English` en français —
et tout l'écran bascule à chaud.

**Ce que la liste des rapports ajoute** (elle est imbriquée : `Échap` revient au sélecteur de dossiers) :

| Touche | Action |
|--------|--------|
| `Espace` | Marquer / démarquer un rapport pour suppression (les lignes marquées sont en rouge) |
| `a` | Marquer tous les rapports |
| `d` | Supprimer les rapports marqués (confirmation requise) |
| `u` | Démarquer tout — affiché seulement une fois quelque chose de marqué |

### Visualiseur de rapport

Appuyer sur `Entrée` sur un rapport ouvre un visualiseur scrollable en lecture
seule. C'est un écran imbriqué : `Échap` revient à la liste, et `q` ne quitte
pas :

| Touche | Action |
|--------|--------|
| `↑` / `↓` / `j` / `k` / `PgUp` / `PgDn` / `g` / `G` | Faire défiler (le socle commun) |
| `←` / `→` | Rapport plus ancien / plus récent, sans revenir à la liste (depuis la v0.32.0) |
| `s` | Basculer entre log complet et vue résumé (score + constats ALERT/WARN uniquement) |
| `n` | Afficher / masquer le bloc des notes — proposé quand le rapport a des notes |
| `a` | Gérer les notes (ajouter, modifier, retirer, purger, journal) |
| `c` | Afficher / masquer la comparaison avec le rapport précédent |
| `h` | Afficher / masquer l'historique des rapports de cet hôte |
| `b` | Afficher / masquer le calcul du score, comme `--breakdown` l'affiche (depuis la v0.40.0) |
| `t` | Tout afficher d'un coup — les notes avec leur journal, la comparaison, l'historique, le calcul, la numérotation des lignes (journal complet) ; à nouveau, tout masquer (depuis la v0.43.0) |
| `#` | Numéroter les lignes du rapport (log complet seulement) |
| `Échap` | Revenir à la liste des rapports |

**Les blocs au-dessus du rapport** (depuis la v0.39.0). Les notes, la comparaison,
l'historique et (depuis la v0.40.0) le calcul sont des blocs à part, affichés
au-dessus du rapport et jamais dedans, dans cet ordre. À l'ouverture du
visualiseur, les notes sont ouvertes (si le rapport en a), la comparaison,
l'historique et le calcul fermés, la numérotation désactivée. Un bloc que vous ouvrez ou fermez le reste quand `←` / `→` passent à
un autre rapport, et montre le contenu de ce rapport (ou dit qu'il n'y en a
pas) ; il ne change que si vous appuyez de nouveau sur sa touche. Sortir du
visualiseur et y revenir repart de zéro.

**La numérotation** (`#`) numérote les lignes du rapport lui-même, jamais les
blocs : un numéro désigne toujours une ligne du fichier. Elle n'est proposée
que sur le log complet : les lignes de la vue résumé ne se suivent pas.

#### Les notes sur un rapport

Les notes consignent ce qui a été fait après un audit — *« UFW réactivé après
l'audit »* — à côté du rapport, jamais dedans : le rapport est une preuve et
n'est jamais réécrit. `a` ouvre leurs actions ; chaque invite et chaque
confirmation s'affiche sur la ligne de contexte, et `Échap` revient au
visualiseur :

| Touche | Action |
|--------|--------|
| `a` | Ajouter une note — vous tapez le texte ; la date et l'heure sont ajoutées |
| `e` | Modifier une note — elle est marquée *éditée*, avec quand et par qui ; son ancien texte reste dans le journal |
| `r` | Retirer des notes — une, plusieurs (`1,3`, `2-5`) ou `all` ; elles quittent le bloc ; leur texte reste dans le journal |
| `p` | Purger des notes — une, plusieurs ou `all` ; leur texte est effacé de toutes les versions, un motif est obligatoire ; qui, quand et pourquoi sont gardés |
| `v` | Afficher / masquer le journal : toutes les actions sur les notes, de la plus ancienne |

Les notes visées par une action sont lues d'abord — avant de demander un motif
ou une confirmation — selon la règle de toute liste de numéros
(CONVENTIONS.md) : un intervalle prend les notes qui existent entre ses bornes
(`2-4` sur les notes 1, 2 et 4 prend 2 et 4) ; un numéro donné seul doit être une
note, sinon la sélection est refusée et le numéro est dit. Plusieurs notes sont
retirées ou purgées en une seule écriture, toutes ou aucune. Chaque retrait et chaque purge
se confirme sur la ligne de contexte : la question, puis *Appuyez sur y pour
confirmer, sur toute autre touche pour annuler.* (la formulation de toute
confirmation, CONVENTIONS.md).

**Modifier ou purger.** Modifier corrige une note et garde chaque version : sur
un serveur partagé entre plusieurs opérateurs, personne ne réécrit une note sans
laisser de trace. Un secret collé par erreur se **purge** : son texte quitte
chaque ligne du journal, versions précédentes comprises, et il ne reste que
*« purgée le … par … (motif) »*.

**Qui a fait quoi.** Chaque action enregistre son auteur et son heure. Sur un
serveur partagé, tout le monde lance `sudo bob`, donc « root » ne dirait rien :
BOB enregistre le compte que désigne l'identifiant de connexion du noyau
(loginuid) — sur l'hôte de test, il a survécu à `sudo`, `sudo -i`, `sudo su -`
et `sudo env -i` (mesuré) — et à côté la déclaration `SUDO_USER`/`DOAS_USER`,
affichée `alice (sudo: bob)` quand les deux diffèrent. Le loginuid est
l'identité de la session telle que le noyau la garde, pas une preuve de qui est
au clavier. Sans loginuid — mesuré pour un service systemd —, c'est la
déclaration qui nomme l'auteur, sinon le compte effectif. Les heures sont
enregistrées avec leur décalage par rapport à UTC et affichées dans l'heure
locale de celui qui lit.

**Qui peut l'écrire.** Les notes s'écrivent avec BOB lancé en root
(`sudo bob --manage-logs`) : le journal appartient à root, en `0640`, dans le
groupe du rapport — le propriétaire du rapport peut le lire, seul root peut en
modifier le contenu. Quand il appartenait au propriétaire du rapport, comme
d'abord conçu, ce compte l'a réécrit sans root et BOB l'a relu comme intact
(mesuré sur l'hôte de test). Le propriétaire du répertoire du rapport peut
toujours supprimer le fichier ou en mettre un autre à sa place : un fichier de
notes qui n'appartient pas à root est dit ne pas être de BOB, et BOB n'y écrit
plus rien ; un lien à sa place n'est pas suivi.

**Ce que le journal peut montrer, et ce qu'il ne peut pas.** Il permet de
détecter certaines altérations ; il ne les empêche pas. Chaque ligne porte
l'empreinte de la précédente, calculée sur la ligne sans le texte de la note ni
son sel — donc sur l'empreinte salée du texte, qui vérifie le texte tant qu'il
est là. Un texte modifié (son empreinte salée ne correspond plus) ou un auteur
modifié, une ligne retirée du milieu ou déplacée hors de BOB, ou un journal
recopié à côté d'un autre rapport, se voit : le bloc dit *« journal modifié
hors de BOB à la ligne N »*, et BOB n'y écrit plus rien. Les empreintes ne sont
pas une signature : qui peut écrire le fichier — root — peut recalculer toute la
chaîne sans y laisser de trace. Des lignes retirées à la **fin**, ou la
suppression du fichier par le propriétaire du répertoire qui le contient, ne
laissent aucune trace dans le fichier lui-même. Sur l'hôte de test (une Linux
Mint 22.3 dont le réglage d'audit ne rend pas le loginuid immuable), root
pouvait réécrire son propre loginuid : rien dans un fichier que root peut écrire
n'empêche root de mentir sur son identité. Une purge efface le texte et son sel
du journal — l'empreinte laissée ne peut plus être confrontée à des textes
candidats ; les copies faites hors de BOB — sauvegardes, instantanés du système
de fichiers — gardent ce qu'elles contiennent.

#### Comparaison et historique

**`c` — la comparaison** avec le rapport précédent **du même hôte** dans le
dossier (un dossier partagé peut contenir plusieurs hôtes), dite exactement
comme le dit `--diff` : score, constats apparus ou résolus, ports, services.
**`h` — l'historique** des rapports de cet hôte dans le dossier, jusqu'à celui
affiché, dessiné comme le dessine `--history`. Les deux viennent d'un petit
fichier d'état que BOB écrit à côté de chaque rapport `-d` depuis la v0.39.0 ; un
rapport écrit avant n'en a pas, et le bloc le dit — aucune comparaison n'est
devinée à partir du texte du rapport.
L'historique montre la fin de chaque audit en UTC, comme `--history` ; le nom
d'un rapport porte son début, en heure locale.

**`b` — calcul** du score du rapport, affiché par le code même de `--breakdown`
à partir de ce que le moteur tenait quand le rapport a été écrit — déductions,
plafonds d'outil, plafond général, domaines, moyenne et score final. Gardé dans
le fichier d'état depuis la v0.40.0 ; un rapport écrit avant dit qu'il n'a pas
ce détail, plutôt que d'en recalculer un à partir du texte du rapport. Le bloc
montre chaque ligne avec son signe (✔ ⚠ ℹ ✖), là où la sortie texte ajoute
`[ATTENTION]`, `[INFO]`, `[ALERTE]`.

#### Les fichiers à côté de chaque rapport

Trois fichiers, deux niveaux de confiance :

| Fichier | Propriétaire, mode | Qui peut le modifier |
|---------|--------------------|----------------------|
| `bob_<date>.log` — le rapport | le propriétaire du rapport, `0600` | son propriétaire |
| `bob_<date>.log.state` — son état, pour la comparaison, l'historique et le calcul | le propriétaire du rapport, `0600` | son propriétaire — la comparaison et l'historique qui en sont tirés ne valent donc pas plus que le rapport |
| `bob_<date>.log.note` — ses notes | root, `0640`, groupe du rapport | root pour le contenu ; le propriétaire du répertoire peut supprimer ou remplacer le fichier, et BOB le dit |

Les deux fichiers compagnons ne sont jamais listés — chaque liste ne montre que
`bob_*.log` — et sont déplacés et supprimés avec leur rapport.

### Mode texte de repli (non-TTY)

Utilisé automatiquement quand stdout n'est pas un terminal :

| Saisie | Action |
|--------|--------|
| `1`, `3`, `1,3`, `2-5` | Supprimer le(s) rapport(s) par numéro (confirmation requise, `[y/N]`, depuis la v0.39.0 ; un numéro sans rapport est refusé et dit, un intervalle prend les rapports qui existent) |
| `all` | Supprimer tous les rapports visibles (confirmation requise) |
| `c` | Changer l'emplacement de stockage |
| Entrée / `q` | Quitter |

### Changer l'emplacement de stockage

Appuyez sur `c` pour saisir un nouveau chemin. Si des rapports existent dans le répertoire actuel, la question suivante apparaît :

```
Déplacer 28 rapport(s) vers le nouvel emplacement ? [y/N]
```

- **y** — tous les rapports visibles sont déplacés vers le nouveau chemin, chacun avec ses notes et son état, à travers des descripteurs vérifiés des deux répertoires (depuis la v0.26.1, un répertoire sous votre home qui se résout hors de lui est refusé)
- **n / Entrée** — les rapports restent dans l'ancien répertoire ; l'ancien chemin est mémorisé

### Vue multi-répertoires

Dans le mode texte de repli, si vous avez changé l'emplacement sans déplacer les rapports, tous les répertoires connus sont affichés ensemble dans une liste unifiée (l'écran curses les montre plutôt comme dossiers dans son sélecteur) :

```
  Rapports dans : /var/log/bob-audits  [actuel]

  ℹ Aucun rapport trouvé

  ─── Emplacement précédent : /home/user/.local/share/bob/logs ───

  [ 1]  bob_20260416_053234.log  (20 Ko)  2026-04-16 05:32
  ...
  [28]  bob_20260413_124813.log  (19 Ko)  2026-04-13 12:48
```

Tous les éléments partagent un index continu — suppression, sélection ou `all` fonctionnent quel que soit le répertoire d'origine. Les anciens répertoires devenus vides sont automatiquement retirés de la liste.

---

## Configuration Postfix pour les emails HTML

Les rapports cron sont envoyés au format HTML (MIME multipart/alternative) plutôt que texte brut. Postfix doit être installé et configuré pour relayer ces emails via un serveur SMTP externe.

### Étape 1 — Installer Postfix et mailutils

```bash
sudo apt install postfix mailutils
```

Pendant l'installation, un wizard interactif s'affiche :
- **General type of mail configuration** → choisir **"Internet Site"**
- **System mail name** → votre hostname ou domaine (ex : `monserveur.com`)

### Étape 2 — Configurer un relais SMTP

Un desktop ou un serveur domestique ne peut généralement pas envoyer directement sur internet : beaucoup de FAI bloquent le port 25 en sortie. Passez par un fournisseur SMTP externe.

**Exemple avec Mailo :**

```bash
sudo postconf -e "relayhost = [smtp.mailo.com]:587"
sudo postconf -e "smtp_sasl_auth_enable = yes"
sudo postconf -e "smtp_sasl_security_options = noanonymous"
sudo postconf -e "smtp_tls_security_level = encrypt"
sudo postconf -e "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd"
sudo postconf -e "inet_interfaces = loopback-only"
```

> `inet_interfaces = loopback-only` empêche Postfix d'écouter sur les interfaces réseau externes — recommandé pour les desktops et postes de travail.

**Exemple avec Gmail** (nécessite un [App Password](https://myaccount.google.com/apppasswords) — la 2FA doit être activée) :

```bash
sudo postconf -e "relayhost = [smtp.gmail.com]:587"
sudo postconf -e "smtp_sasl_auth_enable = yes"
sudo postconf -e "smtp_sasl_security_options = noanonymous"
sudo postconf -e "smtp_tls_security_level = encrypt"
sudo postconf -e "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd"
sudo postconf -e "inet_interfaces = loopback-only"
```

### Étape 3 — Enregistrer les identifiants SMTP

Utilisez un éditeur de texte pour éviter les problèmes avec les caractères spéciaux dans les mots de passe :

```bash
sudo nano /etc/postfix/sasl_passwd
```

Ajoutez une ligne au format suivant :
```
[smtp.mailo.com]:587 vous@mailo.com:VOTRE_MOT_DE_PASSE
```

Puis sécurisez et compilez le fichier :

```bash
sudo chmod 600 /etc/postfix/sasl_passwd
sudo postmap /etc/postfix/sasl_passwd
```

### Étape 4 — Réécrire l'adresse d'expéditeur

Postfix envoie les emails avec l'adresse système locale (ex : `root@hostname.lan`), rejetée par les serveurs SMTP externes. Il faut la réécrire avec votre vraie adresse :

```bash
sudo bash -c 'cat > /etc/postfix/sender_canonical << EOF
/^.*@/ vous@mailo.com
EOF'

sudo postmap /etc/postfix/sender_canonical
sudo postconf -e "sender_canonical_maps = regexp:/etc/postfix/sender_canonical"
```

### Étape 5 — Appliquer et tester

```bash
sudo systemctl restart postfix

echo "Test BOB" | mail -s "Test Postfix" vous@mailo.com
sudo tail -10 /var/log/mail.log
```

Résultat attendu dans les logs :
```
status=sent (250 Message to be delivered)
```

### Problèmes courants

#### Erreur : « 553 bad address format »

La réécriture de l'expéditeur (étape 4) n'a pas été appliquée. Vérifiez que `sender_canonical_maps` est actif :

```bash
sudo postconf sender_canonical_maps
# Attendu : sender_canonical_maps = regexp:/etc/postfix/sender_canonical
```

#### Erreur : « 530 Authentication required » ou « 535 Authentication failed »

Les identifiants dans `/etc/postfix/sasl_passwd` sont incorrects ou le fichier n'a pas été compilé. Rééditez le fichier avec `sudo nano`, puis relancez :

```bash
sudo postmap /etc/postfix/sasl_passwd
sudo systemctl restart postfix
```

Pour Gmail, assurez-vous d'utiliser un **App Password** et non votre mot de passe Google habituel.

### Notes techniques

- Le script généré n'exporte `PYTHONPATH` que lorsque le paquet `bob` ne peut pas être importé sans lui (installation hors pip ; depuis la v0.16.2)
- L'enveloppe SMTP utilise `sendmail -t -f` pour contrôler l'adresse d'expéditeur
- Pas de dépendances externes (HTML généré en pur Python)

---

© 2026 Cédric Clauzel
