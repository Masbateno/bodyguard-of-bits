*[Read in English](AUTOMATION.md)*

# Automatisation — BOB

Ce document explique comment configurer BOB pour s'exécuter automatiquement selon un planning et vous notifier en cas de problème.

---

## Configuration rapide

```bash
sudo bob --install-cron
```

Le wizard vous guide en 4 étapes :

1. **Nom** — un court libellé pour ce cron (ex : `nightly`, `weekly`). Appuyez sur Entrée pour utiliser le nom suggéré.
2. **Planification** — choisissez parmi :
   - Tous les jours
   - Certains jours de la semaine (ex : `1 3 5` pour Lun/Mer/Ven)
   - Certains jours du mois (ex : `1 15` pour le 1er et le 15)
   - Expression cron personnalisée (ex : `0 3 * * 1`)
3. **Heure** — heure d'exécution au format `HH:MM` (défaut : `03:00`). Non affichée pour les expressions personnalisées.
4. **Email** — adresse de notification optionnelle. Laissez vide pour désactiver.

Un aperçu en langage naturel est affiché avant confirmation :
```
  → Planification : tous les lundi, mercredi, vendredi à 02:30
```

### Fichiers créés

- `/usr/local/bin/bob-{nom}` — script wrapper
- `/etc/cron.d/bob-{nom}` — entrée cron système

---

## Gestion des crons

```bash
sudo bob --manage-cron
```

Liste tous les crons installés avec leur planning et leur email de notification. Le menu boucle jusqu'à ce que vous quittiez explicitement :

```
  1. nightly              tous les jours à 03:00
     → email: vous@exemple.com
  2. weekly-monday        tous les lundi à 02:00

  Numéro pour modifier, 'e:N' pour l'email, 'd:N' / 'd:1,3' / 'd:1-3' / 'd:all' pour supprimer, 'm' pour le carnet, Entrée pour quitter
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

Entrez `d:N` pour supprimer un cron, ou utilisez liste, plage ou `all` pour une suppression en lot :

```
  1. nightly              tous les jours à 03:00
  2. weekly               tous les lundi à 02:00

  Numéro pour modifier, 'e:N' pour l'email, 'd:N' / 'd:1,3' / 'd:1-3' / 'd:all' pour supprimer, 'm' pour le carnet, Entrée pour quitter
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

  Numéro à supprimer, '1,3' ou '1-3' pour une sélection, 'all' pour tout supprimer, 'a' pour ajouter, Entrée pour quitter
  >
```

| Commande | Action |
|----------|--------|
| `a` | Ajouter une nouvelle adresse validée |
| `N` | Supprimer l'adresse N |
| `1,3` | Supprimer les adresses 1 et 3 |
| `1-3` | Supprimer les adresses 1, 2 et 3 |
| `all` | Supprimer toutes les adresses enregistrées |
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

`--install-cron` détecte automatiquement votre MTA (Postfix, Exim, msmtp, ssmtp) et avertit si aucun n'est trouvé.

La notification est envoyée **uniquement si l'audit détecte des alertes ou des avertissements** (code de sortie > 0). Si votre configuration est saine, vous ne recevez rien.

---

## Format des fichiers cron

Chaque fichier cron inclut des métadonnées en commentaires pour l'identification. Les emails multiples sont stockés séparés par des virgules :

```
# BOB cron — généré par bob --install-cron
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

- Une ligne d'en-tête avec l'hôte, le score et le niveau de risque
- Les sous-scores par domaine
- La liste des findings ALERT et WARN (tronquée à 10 au-delà)
- Des attachments color-coded (rouge / orange / vert selon le score)

### Enveloppe JSON générique

Le payload générique est volontairement minimal et stable :

```json
{
  "schema_version": "1",
  "host": "example.local",
  "timestamp": "2026-05-17T18:42:01+02:00",
  "score": 8,
  "risk": "LOW",
  "alerts": [
    {"key": "ssh.permit_root_login", "message": "..."}
  ],
  "warnings": [
    {"key": "hardening.send_redirects", "message": "..."}
  ]
}
```

C'est le même contrat que `bob --json` (clés top-level). À consommer avec des services qui reçoivent du `curl`, des intégrations style Zapier, des agrégateurs de logs ou des endpoints internes custom.

### Comportement

- Le webhook est POSTé **uniquement si des alertes ou avertissements sont présents** (même seuil que les notifications email). Un audit clean ne produit aucune notification.
- `--offline` (ou `-o`) désactive complètement la livraison webhook. À utiliser pour les sandboxes de build distro et environnements air-gapped.
- Un POST webhook échoué **n'affecte pas** le code de sortie de l'audit — c'est une notification best-effort, pas un gate. Les erreurs sont écrites sur stderr.
- Chaque URL webhook est appelée avec un timeout de 5 secondes.

### Combinaison avec cron

Le script wrapper cron généré par `--install-cron` n'inclut actuellement pas de flag `--webhook`. Pour lancer un audit planifié avec livraison webhook, éditer le wrapper généré à `/usr/local/bin/bob-{name}` et ajouter le flag à l'invocation `bob` :

```bash
sudo nano /usr/local/bin/bob-nightly
# remplacer :  /usr/local/bin/bob ... -d
# par :        /usr/local/bin/bob ... -d --webhook https://hooks.slack.com/...
```

---

## Surveillance et suivi

Au-delà des audits planifiés, BOB propose une poignée de flags qui aident les opérateurs à observer l'état du système dans le temps. Ce ne sont pas des "automatisations" au sens cron, mais elles s'intègrent dans la même boîte à outils opérationnelle.

### `--watch=N` — mode surveillance en direct

Relance l'audit toutes les `N` secondes jusqu'à interruption avec `Ctrl-C` :

```bash
sudo bob --watch=60
```

Chaque passe redessine le terminal sur place. Les deltas de score (vs la passe précédente) sont mis en évidence pour que les changements soient faciles à repérer. Cas d'usage :

- Observer un changement de durcissement prendre effet (`sudo sysctl -w ...` → la passe suivante voit le WARN disparaître)
- Démontrer l'audit en live en réunion
- Vérifier un changement fail2ban / pare-feu sans relancer manuellement

`--watch` est incompatible avec `--json`, `--output=csv`, `--output=markdown` et `--html` (utilise la sortie terminal interactive).

### `--diff` — afficher uniquement ce qui a changé

Compare l'audit courant au précédent et n'affiche que le delta :

```bash
sudo bob --diff
```

Forme de la sortie :

```
✔  Résolus depuis le dernier audit (2) :
   - hardening.send_redirects
   - ssh.x11_forwarding
✖  Nouveaux findings depuis le dernier audit (1) :
   - clamav.scan_old
```

Le fichier baseline vit à `~/.config/bob/last_baseline.json` (mode `0600`) et est réécrit à la fin de chaque audit complet. Pour effacer la baseline et repartir à zéro :

```bash
sudo bob --reset-baseline
```

### `--history` — tendance du score dans le temps

Affiche un sparkline des 50 derniers scores d'audit depuis `~/.config/bob/history.jsonl` :

```bash
bob --history
```

```
Historique des scores (50 derniers audits) :
  ▃▃▅▆▇▇▇▇▆▇▇▇▇█████████  courant : 8/10
  ┴─────────────────────┴
  2026-05-10           2026-05-17
```

Le fichier d'historique append une ligne par audit (timestamp + score + niveau) et rotate à 1000 entrées. Pas de sudo requis pour `--history` seul.

### `--breakdown` (`-B`) — transparence du calcul de score

Affiche le calcul complet du score après le résumé d'audit : chaque déduction, chaque plafond, et les scores bruts par domaine avant moyennage.

```bash
sudo bob --breakdown
sudo bob -B                       # forme courte
```

À utiliser quand le score affiché ne correspond pas à votre intuition et que vous voulez savoir *quelles* déductions s'y sont additionnées. La sortie est lisible mais assez verbeuse — typiquement utilisé une fois après un changement de config plutôt qu'en audit de routine.

---

## Gestion des rapports

Pour lister et supprimer les rapports générés :

```bash
sudo bob --manage-logs
```

Dans un terminal interactif, une interface TUI curses s'ouvre. Un mode texte de repli est utilisé quand stdout n'est pas un TTY (pipes, scripts).

### Mode TUI (terminal interactif)

L'interface à curseur affiche tous les rapports avec leur date, taille et score. Un graphique d'historique des scores est affiché en haut.

**Navigation et actions :**

| Touche | Action |
|--------|--------|
| `↑` / `↓` | Déplacer le curseur |
| `Entrée` | Prévisualiser le rapport sélectionné (visualiseur scrollable) |
| `Espace` | Marquer / démarquer un rapport pour suppression |
| `a` | Marquer tous les rapports |
| `d` | Supprimer les rapports marqués (confirmation requise) |
| `u` | Démarquer tout |
| `c` | Changer l'emplacement de stockage |
| `q` | Quitter |

### Visualiseur de rapport

Appuyer sur `Entrée` sur un rapport ouvre un visualiseur scrollable en lecture seule :

| Touche | Action |
|--------|--------|
| `↑` / `↓` / `PgUp` / `PgDn` | Faire défiler |
| `g` | Aller en haut |
| `G` | Aller en bas |
| `s` | Basculer entre log complet et vue résumé (score + findings ALERT/WARN uniquement) |
| `Échap` | Revenir à la liste des rapports |

### Mode texte de repli (non-TTY)

Utilisé automatiquement quand stdout n'est pas un terminal :

| Saisie | Action |
|--------|--------|
| `1`, `3`, `1,3`, `2-5` | Supprimer le(s) rapport(s) par numéro |
| `all` | Supprimer tous les rapports visibles (confirmation requise) |
| `c` | Changer l'emplacement de stockage |
| Entrée / `q` | Quitter |

### Changer l'emplacement de stockage

Appuyez sur `c` pour saisir un nouveau chemin. Si des rapports existent dans le répertoire actuel, la question suivante apparaît :

```
Déplacer 28 rapport(s) vers le nouvel emplacement ? [y/N]
```

- **y** — tous les rapports visibles sont déplacés vers le nouveau chemin via `shutil.move`
- **n / Entrée** — les rapports restent dans l'ancien répertoire ; l'ancien chemin est mémorisé

### Vue multi-répertoires

Si vous avez changé l'emplacement sans déplacer les rapports, tous les répertoires connus sont affichés ensemble dans une liste unifiée :

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

Postfix ne peut pas envoyer directement sur internet depuis un desktop ou un serveur domestique (les FAI bloquent le port 25). Il faut passer par un fournisseur SMTP externe.

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

- Le script généré exporte automatiquement `PYTHONPATH` pour les imports Python
- L'enveloppe SMTP utilise `sendmail -t -f` pour contrôler l'adresse d'expéditeur
- Pas de dépendances externes (HTML généré en pur Python)

---

© 2026 Cédric Clauzel
