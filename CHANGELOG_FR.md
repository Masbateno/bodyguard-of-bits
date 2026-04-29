*[Read in English](CHANGELOG.md)* · *[Journal complet](DOCUMENTS/CHANGELOG_FULL_FR.md)*

# BOB — Journal des modifications

| Version | Date | Résumé |
|---------|------|--------|
| [v0.2.0](#v020) | 01-05-2026 | Refonte du scoring (moyenne domaines · plafond par outil) · détection MTA cron · faux positif kernel `-unsigned` · dominance IoT WARN · bannière orange · 4238/4238 tests |
| [v0.1.1](#v011) | 29-04-2026 | Hotfix — parser fwupd format arbre · message `--install-completion` · renommage colonne panorama · 4206/4206 tests |
| [v0.1.0](#v010) | 26-04-2026 | Version initiale — 46 vérifications · 9 domaines · 32 services · mapping CIS · FR/EN · 4200/4200 tests |

---

## [v0.2.0] — 01-05-2026

Cinq améliorations : refonte du scoring, détection MTA pour le cron, correction du faux positif kernel, correction de la dominance IoT dans les logs, et bannière ASCII orange.

### Refonte du scoring (`bob/scoring.py`, `bob/domain_scores.py`)

**Problème :** le score global était la somme brute de toutes les déductions depuis 10. Huit problèmes mineurs de durcissement sur une machine par ailleurs bien configurée (SSH 10/10, pare-feu 10/10, mises à jour 10/10) pouvaient produire 2/10 CRITIQUE — un score ne reflétant pas la posture réelle.

Deux corrections ciblées :

- **Plafond par outil** — `rootkit`, `clamav` et `file_integrity` contribuent au maximum 1 point de déduction à leur domaine, quel que soit le nombre de findings individuels. Élimine la double pénalité « base rkhunter obsolète + pas de scan enregistré = −2 ».
- **Score global = moyenne des scores de domaine actifs** — le score global est désormais la moyenne arrondie de tous les scores de domaine pour lesquels au moins un finding existe (services non installés exclus). Un domaine Durcissement dégradé ne fait plus s'effondrer le score global quand SSH, pare-feu et mises à jour sont à 10/10.

**Effet sur le cas de référence Debian 13 :** 8 déductions → était 2/10 CRITIQUE, reflète maintenant la plage réelle de 6 à 9/10 selon les domaines actifs.

Nouvelle API : `ScoreEngine.set_global_score()`, `compute_global_from_domains()`, `apply_domain_score_override()`.

### Détection MTA cron (`bob/cron.py`)

**Problème :** l'assistant cron avertissait `'mail' non disponible — installez mailutils` quand `mail` était absent, mais l'envoi réel utilise `sendmail`, pas `mail`. Le conseil était incorrect et incomplet.

Nouveau helper `_detect_mta()` :
- Vérifie `sendmail` (le binaire réellement utilisé pour la livraison)
- Identifie le fournisseur : Postfix, Exim, msmtp, ssmtp
- Affiche `✔ Transport mail : Postfix` quand disponible
- Affiche des instructions d'installation claires en cas d'absence : `sudo apt install postfix` (MTA local) ou `sudo apt install msmtp-mta` (relais via Gmail/SMTP)

### Correction faux positif kernel `-unsigned` (`bob/checks/kernel_modules.py`)

**Problème :** sur Debian avec Secure Boot activé, `linux-image-X-amd64` (signé) et `linux-image-X-amd64-unsigned` sont tous deux installés. Le système démarre correctement le noyau signé, mais BOB signalait `-unsigned` comme « plus récent installé » et avertissait « redémarrage requis ».

Nouveau helper `_strip_unsigned()` : le suffixe `-unsigned` est retiré avant la comparaison de versions. Exécuter le noyau signé alors que seule la variante unsigned de la même version est également installée n'est plus signalé.

### Dominance IoT dans les logs : WARN −1 pt (`bob/checks/logs.py`)

**Problème :** quand une seule IP privée représentait ≥ 70 % du trafic UFW bloqué (≥ 50 entrées), BOB émettait un finding INFO sans déduction de score. La fonctionnalité était documentée comme WARN −1 pt mais l'implémentation utilisait `result.info()` sans appel à `add_deduction()`.

**Correction :** `result.info()` remplacé par `result.warn()` + `result.add_deduction(points=1, key="logs.local_dominance")`. Nouvelle clé de localisation `deduction.local_dominance` ajoutée dans `en.json` et `fr.json`. Trois tests existants dans `tests/test_logs.py` corrigés pour vérifier le niveau WARN et la déduction d'1 point (total inchangé).

### Bannière ASCII orange (`bob/output.py`)

L'art ASCII `BOB` dans la bannière terminal est maintenant affiché en orange bold (`\033[1;38;5;208m`). Les caractères de bordure restent en bleu.

### Tests

4238/4238 (3 tests corrigés dans `tests/test_logs.py` — dominance IoT : INFO→WARN + vérification déduction ; total inchangé)

| Fichier | Nouveaux tests | Couverture |
|---------|----------------|-----------|
| `tests/test_kernel_modules.py` | +6 | Helper `_strip_unsigned` · variantes Debian signé/non-signé · vrai redémarrage toujours détecté |
| `tests/test_cron.py` | +6 | `_detect_mta` — sans sendmail, Postfix, Exim, msmtp, ssmtp, inconnu |
| `tests/test_scoring.py` | +6 | `set_global_score` — override, clamp, niveau, score brut inchangé |
| `tests/test_domain_scores.py` | +14 | Plafonds (rootkit/clamav/file_integrity) · `compute_global_from_domains` · `apply_domain_score_override` · scénario Debian 13 |
| `tests/test_logs.py` | 0 (+3 corrigés) | Dominance IoT : niveau WARN · déduction 1 pt · sous le seuil inchangé |

---

## [v0.1.1] — 29-04-2026

Trois corrections ciblées trouvées lors des premiers lancements sur Ubuntu 26.04 LTS et Debian 13.

### Corrections

- **Parser fwupd format arbre** (`bob/checks/firmware.py`) — fwupd 1.9+ (Ubuntu 26.04+) a changé son format de sortie vers une structure en arbre avec les caractères `├─`, `└─`, `│`. L'ancien parser capturait ces caractères comme noms d'appareils, produisant une sortie corrompue (`│, ├─UEFI CA: (+7)`). Les noms d'appareils sont désormais extraits uniquement depuis les lignes `├─`/`└─`.
- **Message d'erreur `--install-completion`** (`bob/__main__.py`) — les utilisateurs qui lançaient `sudo bob --install-completion` obtenaient `sudo: 'bob': command not found` car sudo utilise un PATH restreint qui n'inclut pas les binaires pipx. Le message d'erreur avertit maintenant explicitement que `sudo bob` ne fonctionnera pas et invite à copier-coller la commande exacte avec le chemin complet.
- **En-tête de colonne du panorama des services** (`bob/locales/en.json`, `bob/locales/fr.json`) — renommé `UFW` → `SCOPE` (EN) / `PORTÉE` (FR). La colonne indique si un service a une exposition internet, pas si une règle UFW active le couvre — l'ancien label créait une fausse impression.

### Tests

4206/4206 (+4 tests de régression pour le parser fwupd format arbre dans `tests/test_firmware.py`)

---

## [v0.1.0] — 26-04-2026

Version initiale de **BOB — Bodyguard Of Bits**.

Auditeur de durcissement Linux avec mapping des benchmarks CIS. S'exécute en root, ne nécessite ni agent ni daemon.

### Vérifications de sécurité

46 vérifications réparties en 9 domaines :

- **Pare-feu** — audit des règles UFW, audit iptables/nftables (quand UFW est inactif), cohérence IPv6, analyse de la pile pare-feu, analyse d'exposition des ports
- **SSH** — 12+ paramètres de configuration (PermitRootLogin, PasswordAuthentication, qualité des clés, etc.)
- **Durcissement noyau** — 20+ paramètres sysctl ; audit des modules noyau ; Secure Boot ; firmware/microcode
- **Services** — 32 services connus avec classification du risque ; audit de l'état des services ; détection du contournement pare-feu Docker
- **Permissions fichiers** — audit SUID/SGID ; fichiers sensibles ; sudoers
- **Comptes utilisateurs** — comptes expirés ; politique de mots de passe ; login.defs ; PAM
- **Système** — mises à jour apt ; unattended-upgrades ; niveau de journalisation UFW ; rotation des logs ; analyse auth.log ; NTP ; Fail2ban ; scan rootkit ; auditd ; intégrité des fichiers (AIDE/Tripwire) ; ClamAV ; AppArmor/SELinux ; backup ; santé disque (SMART) ; mémoire/swap ; expiration certificats TLS/SSL ; timers systemd ; applications desktop ; Samba ; tâches cron ; DDNS
- **Réseau** — contexte IP publique ; détection du type de réseau (serveur/LAN/VPN) ; GeoIP optionnel
- **Docker** — configuration du daemon ; conteneurs privilégiés ; montages hôte

### Mapping des benchmarks CIS

133 entrées : 99 CIS Ubuntu 22.04 · 4 CIS Docker · 34 bonnes pratiques.
Chaque résultat avec un code CIS formel affiche `[CIS:X.Y.Z]` en ligne. Référence complète en mode `--verbose`.
`--explain CLÉ` affiche POURQUOI le résultat est important, COMMENT le corriger, et sa référence CIS.

### Formats de sortie

Terminal (coloré) · JSON · CSV · Markdown · HTML

### Profils d'audit

`server` · `workstation` · `desktop` · `docker` — ajustez la sévérité et ignorez les vérifications non pertinentes selon l'environnement.

### Automatisation

- **Cron** — assistant `--install-cron` ; TUI `--manage-cron` ; jobs nommés dans `/etc/cron.d/bob-{nom}`
- **Webhooks** — JSON générique + Slack (détecté automatiquement par l'URL)
- **Historique des scores** — tendance sparkline sur plusieurs exécutions (`--history`)
- **Scores par domaine** — scores 0–10 par domaine (firewall · SSH · hardening · updates · file_perms)
- **Mode diff** — `--diff` affiche uniquement les changements depuis la dernière baseline
- **Mode watch** — `--watch[=N]` relance toutes les N secondes

### CLI

```
sudo bob [OPTIONS]
bob --explain [CLÉ]   # sans sudo
```

Options clés : `--verbose` · `-d` (français) · `--offline` · `--fix` · `--apply` · `--check=LISTE` · `--skip=LISTE`
`--output-dir` · `--format` · `--target N` · `--min-level NIVEAU`

Complétion bash : `sudo bob --install-completion`

### i18n

Anglais et français (`--french` / `-d`).

### Installation

```
pipx install bodyguard-of-bits
sudo bob
```
